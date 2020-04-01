/*
 * filesystem.go - Contains the functionality for a specific filesystem. This
 * includes the commands to setup the filesystem, apply policies, and locate
 * metadata.
 *
 * Copyright 2017 Google Inc.
 * Author: Joe Richey (joerichey@google.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

// Package filesystem deals with the structure of the files on disk used to
// store the metadata for fscrypt. Specifically, this package includes:
//	- mountpoint management (mountpoint.go)
//		- querying existing mounted filesystems
//		- getting filesystems from a UUID
//		- finding the filesystem for a specific path
//	- metadata organization (filesystem.go)
//		- setting up a mounted filesystem for use with fscrypt
//		- adding/querying/deleting metadata
//		- making links to other filesystems' metadata
//		- following links to get data from other filesystems
package filesystem

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/util"
)

// Filesystem error values
var (
	ErrNotAMountpoint  = errors.New("not a mountpoint")
	ErrAlreadySetup    = errors.New("already setup for use with fscrypt")
	ErrNotSetup        = errors.New("not setup for use with fscrypt")
	ErrNoMetadata      = errors.New("could not find metadata")
	ErrLinkedProtector = errors.New("not a regular protector")
	ErrInvalidMetadata = errors.New("provided metadata is invalid")
	ErrFollowLink      = errors.New("cannot follow filesystem link")
	ErrLinkExpired     = errors.New("no longer exists on linked filesystem")
	ErrMakeLink        = util.SystemError("cannot create filesystem link")
	ErrGlobalMountInfo = util.SystemError("creating global mountpoint list failed")
	ErrCorruptMetadata = util.SystemError("on-disk metadata is corrupt")
)

// Mount contains information for a specific mounted filesystem.
//	Path           - Absolute path where the directory is mounted
//	FilesystemType - Type of the mounted filesystem, e.g. "ext4"
//	Device         - Device for filesystem (empty string if we cannot find one)
//	DeviceNumber   - Device number of the filesystem.  This is set even if
//			 Device isn't, since all filesystems have a device
//			 number assigned by the kernel, even pseudo-filesystems.
//	Subtree        - The mounted subtree of the filesystem.  This is usually
//			 "/", meaning that the entire filesystem is mounted, but
//			 it can differ for bind mounts.
//	ReadOnly       - True if this is a read-only mount
//
// In order to use a Mount to store fscrypt metadata, some directories must be
// setup first. Specifically, the directories created look like:
// <mountpoint>
// └── .fscrypt
//     ├── policies
//     └── protectors
//
// These "policies" and "protectors" directories will contain files that are
// the corresponding metadata structures for policies and protectors. The public
// interface includes functions for setting up these directories and Adding,
// Getting, and Removing these files.
//
// There is also the ability to reference another filesystem's metadata. This is
// used when a Policy on filesystem A is protected with Protector on filesystem
// B. In this scenario, we store a "link file" in the protectors directory whose
// contents look like "UUID=3a6d9a76-47f0-4f13-81bf-3332fbe984fb".
//
// We also allow ".fscrypt" to be a symlink which was previously created. This
// allows login protectors to be created when the root filesystem is read-only,
// provided that "/.fscrypt" is a symlink pointing to a writable location.
type Mount struct {
	Path           string
	FilesystemType string
	Device         string
	DeviceNumber   DeviceNumber
	Subtree        string
	ReadOnly       bool
}

// PathSorter allows mounts to be sorted by Path.
type PathSorter []*Mount

func (p PathSorter) Len() int           { return len(p) }
func (p PathSorter) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PathSorter) Less(i, j int) bool { return p[i].Path < p[j].Path }

const (
	// Names of the various directories used in fscrypt
	baseDirName       = ".fscrypt"
	policyDirName     = "policies"
	protectorDirName  = "protectors"
	tempPrefix        = ".tmp"
	linkFileExtension = ".link"

	// The base directory should be read-only (except for the creator)
	basePermissions = 0755
	// The subdirectories should be writable to everyone, but they have the
	// sticky bit set so users cannot delete other users' metadata.
	dirPermissions = os.ModeSticky | 0777
	// The metadata files are globally visible, but can only be deleted by
	// the user that created them
	filePermissions = 0644
)

func (m *Mount) String() string {
	return fmt.Sprintf(`%s
	FilesystemType: %s
	Device:         %s`, m.Path, m.FilesystemType, m.Device)
}

// BaseDir returns the path to the base fscrypt directory for this filesystem.
func (m *Mount) BaseDir() string {
	rawBaseDir := filepath.Join(m.Path, baseDirName)
	// We allow the base directory to be a symlink, but some callers need
	// the real path, so dereference the symlink here if needed. Since the
	// directory the symlink points to may not exist yet, we have to read
	// the symlink manually rather than use filepath.EvalSymlinks.
	target, err := os.Readlink(rawBaseDir)
	if err != nil {
		return rawBaseDir // not a symlink
	}
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(m.Path, target)
}

// ProtectorDir returns the directory containing the protector metadata.
func (m *Mount) ProtectorDir() string {
	return filepath.Join(m.BaseDir(), protectorDirName)
}

// protectorPath returns the full path to a regular protector file with the
// specified descriptor.
func (m *Mount) protectorPath(descriptor string) string {
	return filepath.Join(m.ProtectorDir(), descriptor)
}

// linkedProtectorPath returns the full path to a linked protector file with the
// specified descriptor.
func (m *Mount) linkedProtectorPath(descriptor string) string {
	return m.protectorPath(descriptor) + linkFileExtension
}

// PolicyDir returns the directory containing the policy metadata.
func (m *Mount) PolicyDir() string {
	return filepath.Join(m.BaseDir(), policyDirName)
}

// policyPath returns the full path to a regular policy file with the
// specified descriptor.
func (m *Mount) policyPath(descriptor string) string {
	return filepath.Join(m.PolicyDir(), descriptor)
}

// tempMount creates a temporary directory alongside this Mount's base fscrypt
// directory and returns a temporary Mount which represents this temporary
// directory. The caller is responsible for removing this temporary directory.
func (m *Mount) tempMount() (*Mount, error) {
	tempDir, err := ioutil.TempDir(filepath.Dir(m.BaseDir()), tempPrefix)
	return &Mount{Path: tempDir}, err
}

// err modifies an error to contain the path of this filesystem.
func (m *Mount) err(err error) error {
	return errors.Wrapf(err, "filesystem %s", m.Path)
}

// CheckSupport returns an error if this filesystem does not support filesystem
// encryption.
func (m *Mount) CheckSupport() error {
	return m.err(metadata.CheckSupport(m.Path))
}

// CheckSetup returns an error if all the fscrypt metadata directories do not
// exist. Will log any unexpected errors or incorrect permissions.
func (m *Mount) CheckSetup() error {
	// Run all the checks so we will always get all the warnings
	baseGood := isDirCheckPerm(m.BaseDir(), basePermissions)
	policyGood := isDirCheckPerm(m.PolicyDir(), dirPermissions)
	protectorGood := isDirCheckPerm(m.ProtectorDir(), dirPermissions)

	if baseGood && policyGood && protectorGood {
		return nil
	}
	return m.err(ErrNotSetup)
}

// makeDirectories creates the three metadata directories with the correct
// permissions. Note that this function overrides the umask.
func (m *Mount) makeDirectories() error {
	// Zero the umask so we get the permissions we want
	oldMask := unix.Umask(0)
	defer func() {
		unix.Umask(oldMask)
	}()

	if err := os.Mkdir(m.BaseDir(), basePermissions); err != nil {
		return err
	}
	if err := os.Mkdir(m.PolicyDir(), dirPermissions); err != nil {
		return err
	}
	return os.Mkdir(m.ProtectorDir(), dirPermissions)
}

// Setup sets up the filesystem for use with fscrypt. Note that this merely
// creates the appropriate files on the filesystem. It does not actually modify
// the filesystem's feature flags. This operation is atomic; it either succeeds
// or no files in the baseDir are created.
func (m *Mount) Setup() error {
	if m.CheckSetup() == nil {
		return m.err(ErrAlreadySetup)
	}
	// We build the directories under a temp Mount and then move into place.
	temp, err := m.tempMount()
	if err != nil {
		return m.err(err)
	}
	defer os.RemoveAll(temp.Path)

	if err = temp.makeDirectories(); err != nil {
		return m.err(err)
	}

	// Atomically move directory into place.
	return m.err(os.Rename(temp.BaseDir(), m.BaseDir()))
}

// RemoveAllMetadata removes all the policy and protector metadata from the
// filesystem. This operation is atomic; it either succeeds or no files in the
// baseDir are removed.
// WARNING: Will cause data loss if the metadata is used to encrypt
// directories (this could include directories on other filesystems).
func (m *Mount) RemoveAllMetadata() error {
	if err := m.CheckSetup(); err != nil {
		return err
	}
	// temp will hold the old metadata temporarily
	temp, err := m.tempMount()
	if err != nil {
		return m.err(err)
	}
	defer os.RemoveAll(temp.Path)

	// Move directory into temp (to be destroyed on defer)
	return m.err(os.Rename(m.BaseDir(), temp.BaseDir()))
}

func syncDirectory(dirPath string) error {
	dirFile, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	if err = dirFile.Sync(); err != nil {
		dirFile.Close()
		return err
	}
	return dirFile.Close()
}

// writeDataAtomic writes the data to the path such that the data is either
// written to stable storage or an error is returned.
func (m *Mount) writeDataAtomic(path string, data []byte) error {
	// Write the data to a temporary file, sync it, then rename into place
	// so that the operation will be atomic.
	dirPath := filepath.Dir(path)
	tempFile, err := ioutil.TempFile(dirPath, tempPrefix)
	if err != nil {
		return err
	}
	defer os.Remove(tempFile.Name())

	// TempFile() creates the file with mode 0600.  Change it to 0644.
	if err = tempFile.Chmod(filePermissions); err != nil {
		tempFile.Close()
		return err
	}
	if _, err = tempFile.Write(data); err != nil {
		tempFile.Close()
		return err
	}
	if err = tempFile.Sync(); err != nil {
		tempFile.Close()
		return err
	}
	if err = tempFile.Close(); err != nil {
		return err
	}

	if err = os.Rename(tempFile.Name(), path); err != nil {
		return err
	}
	// Ensure the rename has been persisted before returning success.
	return syncDirectory(dirPath)
}

// addMetadata writes the metadata structure to the file with the specified
// path. This will overwrite any existing data. The operation is atomic.
func (m *Mount) addMetadata(path string, md metadata.Metadata) error {
	if err := md.CheckValidity(); err != nil {
		return errors.Wrap(ErrInvalidMetadata, err.Error())
	}

	data, err := proto.Marshal(md)
	if err != nil {
		return err
	}

	log.Printf("writing metadata to %q", path)
	return m.writeDataAtomic(path, data)
}

// getMetadata reads the metadata structure from the file with the specified
// path. Only reads normal metadata files, not linked metadata.
func (m *Mount) getMetadata(path string, md metadata.Metadata) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("could not read metadata at %q", path)
		if os.IsNotExist(err) {
			return errors.Wrapf(ErrNoMetadata, "descriptor %s", filepath.Base(path))
		}
		return err
	}

	if err := proto.Unmarshal(data, md); err != nil {
		return errors.Wrap(ErrCorruptMetadata, err.Error())
	}

	if err := md.CheckValidity(); err != nil {
		log.Printf("metadata at %q is not valid", path)
		return errors.Wrap(ErrCorruptMetadata, err.Error())
	}

	log.Printf("successfully read metadata from %q", path)
	return nil
}

// removeMetadata deletes the metadata struct from the file with the specified
// path. Works with regular or linked metadata.
func (m *Mount) removeMetadata(path string) error {
	if err := os.Remove(path); err != nil {
		log.Printf("could not remove metadata at %q", path)
		if os.IsNotExist(err) {
			return errors.Wrapf(ErrNoMetadata, "descriptor %s", filepath.Base(path))
		}
		return err
	}

	log.Printf("successfully removed metadata at %q", path)
	return nil
}

// AddProtector adds the protector metadata to this filesystem's storage. This
// will overwrite the value of an existing protector with this descriptor. This
// will fail with ErrLinkedProtector if a linked protector with this descriptor
// already exists on the filesystem.
func (m *Mount) AddProtector(data *metadata.ProtectorData) error {
	if err := m.CheckSetup(); err != nil {
		return err
	}
	if isRegularFile(m.linkedProtectorPath(data.ProtectorDescriptor)) {
		return m.err(ErrLinkedProtector)
	}
	path := m.protectorPath(data.ProtectorDescriptor)
	return m.err(m.addMetadata(path, data))
}

// AddLinkedProtector adds a link in this filesystem to the protector metadata
// in the dest filesystem, if one doesn't already exist.  On success, the return
// value is a nil error and a bool that is true iff the link is newly created.
func (m *Mount) AddLinkedProtector(descriptor string, dest *Mount) (bool, error) {
	if err := m.CheckSetup(); err != nil {
		return false, err
	}
	// Check that the link is good (descriptor exists, filesystem has UUID).
	if _, err := dest.GetRegularProtector(descriptor); err != nil {
		return false, err
	}

	linkPath := m.linkedProtectorPath(descriptor)

	// Check whether the link already exists.
	existingLink, err := ioutil.ReadFile(linkPath)
	if err == nil {
		existingLinkedMnt, err := getMountFromLink(string(existingLink))
		if err != nil {
			return false, err
		}
		if existingLinkedMnt != dest {
			return false, errors.Wrapf(ErrFollowLink, "link %q points to %q, but expected %q",
				linkPath, existingLinkedMnt.Path, dest.Path)
		}
		return false, nil
	}
	if !os.IsNotExist(err) {
		return false, err
	}

	// Right now, we only make links using UUIDs.
	var newLink string
	newLink, err = makeLink(dest, "UUID")
	if err != nil {
		return false, dest.err(err)
	}
	return true, m.err(m.writeDataAtomic(linkPath, []byte(newLink)))
}

// GetRegularProtector looks up the protector metadata by descriptor. This will
// fail with ErrNoMetadata if the descriptor is a linked protector.
func (m *Mount) GetRegularProtector(descriptor string) (*metadata.ProtectorData, error) {
	if err := m.CheckSetup(); err != nil {
		return nil, err
	}
	data := new(metadata.ProtectorData)
	path := m.protectorPath(descriptor)
	return data, m.err(m.getMetadata(path, data))
}

// GetProtector returns the Mount of the filesystem containing the information
// and that protector's data. If the descriptor is a regular (not linked)
// protector, the mount will return itself.
func (m *Mount) GetProtector(descriptor string) (*Mount, *metadata.ProtectorData, error) {
	if err := m.CheckSetup(); err != nil {
		return nil, nil, err
	}
	// Get the link data from the link file
	link, err := ioutil.ReadFile(m.linkedProtectorPath(descriptor))
	if err != nil {
		// If the link doesn't exist, try for a regular protector.
		if os.IsNotExist(err) {
			data, err := m.GetRegularProtector(descriptor)
			return m, data, err
		}
		return nil, nil, m.err(err)
	}

	linkedMnt, err := getMountFromLink(string(link))
	if err != nil {
		return nil, nil, m.err(err)
	}
	data, err := linkedMnt.GetRegularProtector(descriptor)
	if err != nil {
		log.Print(err)
		return nil, nil, m.err(errors.Wrapf(ErrLinkExpired, "protector %s", descriptor))
	}
	return linkedMnt, data, nil
}

// RemoveProtector deletes the protector metadata (or a link to another
// filesystem's metadata) from the filesystem storage.
func (m *Mount) RemoveProtector(descriptor string) error {
	if err := m.CheckSetup(); err != nil {
		return err
	}
	// We first try to remove the linkedProtector. If that metadata does not
	// exist, we try to remove the normal protector.
	err := m.removeMetadata(m.linkedProtectorPath(descriptor))
	if errors.Cause(err) == ErrNoMetadata {
		err = m.removeMetadata(m.protectorPath(descriptor))
	}
	return m.err(err)
}

// ListProtectors lists the descriptors of all protectors on this filesystem.
// This does not include linked protectors.
func (m *Mount) ListProtectors() ([]string, error) {
	if err := m.CheckSetup(); err != nil {
		return nil, err
	}
	protectors, err := m.listDirectory(m.ProtectorDir())
	return protectors, m.err(err)
}

// AddPolicy adds the policy metadata to the filesystem storage.
func (m *Mount) AddPolicy(data *metadata.PolicyData) error {
	if err := m.CheckSetup(); err != nil {
		return err
	}

	return m.err(m.addMetadata(m.policyPath(data.KeyDescriptor), data))
}

// GetPolicy looks up the policy metadata by descriptor.
func (m *Mount) GetPolicy(descriptor string) (*metadata.PolicyData, error) {
	if err := m.CheckSetup(); err != nil {
		return nil, err
	}
	data := new(metadata.PolicyData)
	return data, m.err(m.getMetadata(m.policyPath(descriptor), data))
}

// RemovePolicy deletes the policy metadata from the filesystem storage.
func (m *Mount) RemovePolicy(descriptor string) error {
	if err := m.CheckSetup(); err != nil {
		return err
	}
	return m.err(m.removeMetadata(m.policyPath(descriptor)))
}

// ListPolicies lists the descriptors of all policies on this filesystem.
func (m *Mount) ListPolicies() ([]string, error) {
	if err := m.CheckSetup(); err != nil {
		return nil, err
	}
	policies, err := m.listDirectory(m.PolicyDir())
	return policies, m.err(err)
}

// listDirectory returns a list of descriptors for a metadata directory,
// including files which are links to other filesystem's metadata.
func (m *Mount) listDirectory(directoryPath string) ([]string, error) {
	log.Printf("listing descriptors in %q", directoryPath)
	dir, err := os.Open(directoryPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	descriptors := make([]string, 0, len(names))
	for _, name := range names {
		// Be sure to include links as well
		descriptors = append(descriptors, strings.TrimSuffix(name, linkFileExtension))
	}

	log.Printf("found %d descriptor(s)", len(descriptors))
	return descriptors, nil
}

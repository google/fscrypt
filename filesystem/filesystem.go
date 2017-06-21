/*
 * filesystem.go - Contains the a functionality for a specific filesystem. This
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

	"fscrypt/metadata"
	"fscrypt/util"
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
//	Path       - Absolute path where the directory is mounted
//	Filesystem - Name of the mounted filesystem
//	Options    - List of options used when mounting the filesystem
//	Device     - Device for filesystem (empty string if we cannot find one)
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
// contents look like "UUID=3a6d9a76-47f0-4f13-81bf-3332fbe984fb". These
// contents can be anything parsable by libblkid (i.e. anything that could be in
// the Device column of /etc/fstab).
type Mount struct {
	Path       string
	Filesystem string
	Options    []string
	Device     string
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
	Filsystem: %s
	Options:   %v
	Device:    %s`, m.Path, m.Filesystem, m.Options, m.Device)
}

// BaseDir returns the path of the base fscrypt directory on this filesystem.
func (m *Mount) BaseDir() string {
	return filepath.Join(m.Path, baseDirName)
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

// tempMount creates a temporary Mount under the main directory. The path for
// the returned tempMount should be removed by the caller.
func (m *Mount) tempMount() (*Mount, error) {
	trashDir, err := ioutil.TempDir(m.Path, tempPrefix)
	return &Mount{Path: trashDir}, err
}

// err modifies an error to contain the path of this filesystem.
func (m *Mount) err(err error) error {
	return errors.Wrapf(err, "filesystem %s", m.Path)
}

// CheckSetup returns an error if this filesystem does not support fscrypt or
// all the fscrypt metadata directories do not exist. Will log any unexpected
// errors or incorrect permissions.
func (m *Mount) CheckSetup() error {
	if err := metadata.CheckSupport(m.Path); err != nil {
		return m.err(err)
	}
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

// Setup sets up the filesystem for use with fscrypt, note that this merely
// creates the appropriate files on the filesystem. It does not actually modify
// the filesystem's feature flags. This operation is atomic, it either succeeds
// or no files in the baseDir are created.
func (m *Mount) Setup() error {
	switch err := m.CheckSetup(); errors.Cause(err) {
	case ErrNotSetup:
		break
	case nil:
		return m.err(ErrAlreadySetup)
	default:
		return err
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
// filesystem. This operation is atomic, it either succeeds or no files in the
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

// writeDataAtomic writes the data to the path such that the data is either
// written to stable storage or an error is returned.
func (m *Mount) writeDataAtomic(path string, data []byte) error {
	// Write the file to a temporary file then move into place so that the
	// operation will be atomic.
	tempPath := filepath.Join(filepath.Dir(path), tempPrefix+filepath.Base(path))
	tempFile, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE, filePermissions)
	if err != nil {
		return err
	}
	defer os.Remove(tempPath)

	if _, err = tempFile.Write(data); err != nil {
		tempFile.Close()
		return err
	}
	if err = tempFile.Close(); err != nil {
		return err
	}

	return os.Rename(tempPath, path)
}

// addMetadata writes the metadata structure to the file with the specified
// path this will overwrite any existing data. The operation is atomic.
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
// in the dest filesystem.
func (m *Mount) AddLinkedProtector(descriptor string, dest *Mount) error {
	if err := m.CheckSetup(); err != nil {
		return err
	}
	// Check that the link is good (descriptor exists, filesystem has UUID).
	if _, err := dest.GetRegularProtector(descriptor); err != nil {
		return err
	}

	// Right now, we only make links using UUIDs.
	link, err := makeLink(dest, "UUID")
	if err != nil {
		return dest.err(err)
	}

	path := m.linkedProtectorPath(descriptor)
	return m.err(m.writeDataAtomic(path, []byte(link)))
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

	// As the link could refer to multiple filesystems, we check each one
	// for valid metadata.
	mnts, err := getMountsFromLink(string(link))
	if err != nil {
		return nil, nil, m.err(err)
	}

	for _, mnt := range mnts {
		if data, err := mnt.GetRegularProtector(descriptor); err != nil {
			log.Print(err)
		} else {
			return mnt, data, nil
		}
	}
	return nil, nil, m.err(errors.Wrapf(ErrLinkExpired, "protector %s", descriptor))
}

// RemoveProtector deletes the protector metadata (or an link to another
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

	var descriptors []string
	for _, name := range names {
		// Be sure to include links as well
		descriptors = append(descriptors, strings.TrimSuffix(name, linkFileExtension))
	}

	log.Printf("found %d descriptor(s)", len(descriptors))
	return descriptors, nil
}

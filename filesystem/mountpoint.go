/*
 * mountpoint.go - Contains all the functionality for finding mountpoints and
 * using UUIDs to refer to them. Specifically, we can find the mountpoint of a
 * path, get info about a mountpoint, and find mountpoints with a specific UUID.
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

package filesystem

import (
	"io/ioutil"
	"os"
)

/*
#include <mntent.h>      // setmntent, getmntent, endmntent

// The file containing mountpoints info and how we should read it
const char* mountpoints_filename = "/proc/mounts";
const char* read_mode = "r";
*/
import "C"

import (
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

var (
	// These maps hold data about the state of the system's mountpoints.
	mountsByPath   map[string]*Mount
	mountsByDevice map[string][]*Mount
	// Used to make the mount functions thread safe
	mountMutex sync.Mutex
	// True if the maps have been successfully initialized.
	mountsInitialized bool
	// Supported tokens for filesystem links
	uuidToken = "UUID"
	// Location to perform UUID lookup
	uuidDirectory = "/dev/disk/by-uuid"
)

// getMountInfo populates the Mount mappings by parsing the filesystem
// description file using the getmntent functions. Returns ErrBadLoad if the
// Mount mappings cannot be populated.
func getMountInfo() error {
	if mountsInitialized {
		return nil
	}

	// make new maps
	mountsByPath = make(map[string]*Mount)
	mountsByDevice = make(map[string][]*Mount)

	// Load the mount information from mountpoints_filename
	fileHandle := C.setmntent(C.mountpoints_filename, C.read_mode)
	if fileHandle == nil {
		return errors.Wrapf(ErrGlobalMountInfo, "could not read %q",
			C.GoString(C.mountpoints_filename))
	}
	defer C.endmntent(fileHandle)

	for {
		entry := C.getmntent(fileHandle)
		// When getmntent returns nil, we have read all of the entries.
		if entry == nil {
			mountsInitialized = true
			return nil
		}

		// Create the Mount structure by converting types.
		mnt := Mount{
			Path:       C.GoString(entry.mnt_dir),
			Filesystem: C.GoString(entry.mnt_type),
			Options:    strings.Split(C.GoString(entry.mnt_opts), ","),
		}

		// Skip invalid mountpoints
		var err error
		if mnt.Path, err = cannonicalizePath(mnt.Path); err != nil {
			log.Printf("getting mnt_dir: %v", err)
			continue
		}
		// We can only use mountpoints that are directories for fscrypt.
		if !isDir(mnt.Path) {
			log.Printf("mnt_dir %v: not a directory", mnt.Path)
			continue
		}

		// Note this overrides the info if we have seen the mountpoint
		// earlier in the file. This is correct behavior because the
		// filesystems are listed in mount order.
		mountsByPath[mnt.Path] = &mnt

		deviceName, err := cannonicalizePath(C.GoString(entry.mnt_fsname))
		// Only use real valid devices (unlike cgroups, tmpfs, ...)
		if err == nil && isDevice(deviceName) {
			mnt.Device = deviceName
			mountsByDevice[deviceName] = append(mountsByDevice[deviceName], &mnt)
		}
	}
}

// AllFilesystems lists all the Mounts on the current system ordered by path.
// Use CheckSetup() to see if they are used with fscrypt.
func AllFilesystems() ([]*Mount, error) {
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := getMountInfo(); err != nil {
		return nil, err
	}

	mounts := make([]*Mount, 0, len(mountsByPath))
	for _, mount := range mountsByPath {
		mounts = append(mounts, mount)
	}

	sort.Sort(PathSorter(mounts))
	return mounts, nil
}

// UpdateMountInfo updates the filesystem mountpoint maps with the current state
// of the filesystem mountpoints. Returns error if the initialization fails.
func UpdateMountInfo() error {
	mountMutex.Lock()
	defer mountMutex.Unlock()
	mountsInitialized = false
	return getMountInfo()
}

// FindMount returns the corresponding Mount object for some path in a
// filesystem. Note that in the case of a bind mounts there may be two Mount
// objects for the same underlying filesystem. An error is returned if the path
// is invalid or we cannot load the required mount data. If a filesystem has
// been updated since the last call to one of the mount functions, run
// UpdateMountInfo to see changes.
func FindMount(path string) (*Mount, error) {
	path, err := cannonicalizePath(path)
	if err != nil {
		return nil, err
	}

	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err = getMountInfo(); err != nil {
		return nil, err
	}

	// Traverse up the directory tree until we find a mountpoint
	for {
		if mnt, ok := mountsByPath[path]; ok {
			return mnt, nil
		}

		// Move to the parent directory unless we have reached the root.
		parent := filepath.Dir(path)
		if parent == path {
			return nil, errors.Wrap(ErrNotAMountpoint, path)
		}
		path = parent
	}
}

// GetMount returns the Mount object with a matching mountpoint. An error is
// returned if the path is invalid or we cannot load the required mount data. If
// a filesystem has been updated since the last call to one of the mount
// functions, run UpdateMountInfo to see changes.
func GetMount(mountpoint string) (*Mount, error) {
	mountpoint, err := cannonicalizePath(mountpoint)
	if err != nil {
		return nil, err
	}

	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err = getMountInfo(); err != nil {
		return nil, err
	}

	if mnt, ok := mountsByPath[mountpoint]; ok {
		return mnt, nil
	}

	return nil, errors.Wrap(ErrNotAMountpoint, mountpoint)
}

// getMountsFromLink returns the Mount objects which match the provided link.
// This link if formatted as a tag (e.g. <token>=<value>) similar to how they
// apprear in "/etc/fstab". Currently, only "UUID" tokens are supported. Note
// that this can match multiple Mounts (due to the existence of bind mounts). An
// error is returned if the link is invalid or we cannot load the required mount
// data. If a filesystem has been updated since the last call to one of the
// mount functions, run UpdateMountInfo to see the change.
func getMountsFromLink(link string) ([]*Mount, error) {
	// Parse the link
	linkComponents := strings.Split(link, "=")
	if len(linkComponents) != 2 {
		return nil, errors.Wrapf(ErrFollowLink, "link %q format in invalid", link)
	}
	token := linkComponents[0]
	value := linkComponents[1]
	if token != uuidToken {
		return nil, errors.Wrapf(ErrFollowLink, "token type %q not supported", token)
	}

	// See if UUID points to an existing device
	searchPath := filepath.Join(uuidDirectory, value)
	if filepath.Base(searchPath) != value {
		return nil, errors.Wrapf(ErrFollowLink, "value %q is not a UUID", value)
	}
	devicePath, err := cannonicalizePath(searchPath)
	if err != nil {
		return nil, errors.Wrapf(ErrFollowLink, "no device with UUID %q", value)
	}

	// Lookup mountpoints for device in global store
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := getMountInfo(); err != nil {
		return nil, err
	}
	mnts, ok := mountsByDevice[devicePath]
	if !ok {
		return nil, errors.Wrapf(ErrFollowLink, "no mounts for device %q", devicePath)
	}
	return mnts, nil
}

// makeLink returns a link of the form <token>=<value> where value is the tag
// value for the Mount's device. Currently, only "UUID" tokens are supported. An
// error is returned if the mount has no device, or no UUID.
func makeLink(mnt *Mount, token string) (string, error) {
	if token != uuidToken {
		return "", errors.Wrapf(ErrMakeLink, "token type %q not supported", token)
	}
	if mnt.Device == "" {
		return "", errors.Wrapf(ErrMakeLink, "no device for mount %q", mnt.Path)
	}

	dirContents, err := ioutil.ReadDir(uuidDirectory)
	if err != nil {
		return "", errors.Wrap(ErrMakeLink, err.Error())
	}
	for _, fileInfo := range dirContents {
		if fileInfo.Mode()&os.ModeSymlink == 0 {
			continue // Only interested in UUID symlinks
		}
		uuid := fileInfo.Name()
		devicePath, err := cannonicalizePath(filepath.Join(uuidDirectory, uuid))
		if err != nil {
			log.Print(err)
			continue
		}
		if mnt.Device == devicePath {
			return fmt.Sprintf("%s=%s", uuidToken, uuid), nil
		}
	}
	return "", errors.Wrapf(ErrMakeLink, "device %q has no UUID", mnt.Device)
}

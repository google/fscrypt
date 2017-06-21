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

/*
#cgo LDFLAGS: -lblkid
#include <blkid/blkid.h> // blkid functions
#include <stdlib.h>      // free()
#include <mntent.h>      // setmntent, getmntent, endmntent

// The file containing mountpoints info and how we should read it
const char* mountpoints_filename = "/proc/mounts";
const char* read_mode = "r";

// Helper function for freeing strings
void string_free(char* str) { free(str); }

// Helper function to lookup tokens
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
	// Cache for information about the devices
	cache C.blkid_cache
	// Used to make the mount functions thread safe
	mountMutex sync.Mutex
	// True if the maps have been successfully initialized.
	mountsInitialized bool
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

	// Load the device information from the default blkid cache
	if cache != nil {
		C.blkid_put_cache(cache)
	}
	if C.blkid_get_cache(&cache, nil) != 0 {
		return errors.Wrap(ErrGlobalMountInfo, "could not read blkid cache")
	}

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
// This link can be an unparsed tag (e.g. <token>=<value>) or path (e.g.
// /dev/dm-0). The matching rules are determined by libblkid. These are the same
// matching rules for things like UUID=3a6d9a76-47f0-4f13-81bf-3332fbe984fb in
// "/etc/fstab". Note that this can match multiple Mounts. An error is returned
// if the link is invalid or we cannot load the required mount data. If a
// filesystem has been updated since the last call to one of the mount
// functions, run UpdateMountInfo to see the change.
func getMountsFromLink(link string) ([]*Mount, error) {
	// Use blkid_evaluate_spec to get the device name.
	cLink := C.CString(link)
	defer C.string_free(cLink)

	cDeviceName := C.blkid_evaluate_spec(cLink, &cache)
	defer C.string_free(cDeviceName)
	deviceName := C.GoString(cDeviceName)

	log.Printf("blkid_evaluate_spec(%q, <cache>) = %q", link, deviceName)

	if deviceName == "" {
		return nil, errors.Wrapf(ErrFollowLink, "link %q is invalid", link)
	}
	deviceName, err := cannonicalizePath(deviceName)
	if err != nil {
		return nil, err
	}

	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := getMountInfo(); err != nil {
		return nil, err
	}

	if mnts, ok := mountsByDevice[deviceName]; ok {
		return mnts, nil
	}

	return nil, errors.Wrapf(ErrFollowLink, "device %q is invalid", deviceName)
}

// makeLink returns a link of the form <token>=<value> where value is the tag
// value for the Mount's device according to libblkid. An error is returned if
// the device/token pair has no value.
func makeLink(mnt *Mount, token string) (string, error) {
	// The blkid cache may not always hold the canonical device path. To
	// solve this we first use blkid_evaluate_spec to find the right entry
	// in the cache. Then that name is used to get the token value.
	cDevice := C.CString(mnt.Device)
	defer C.string_free(cDevice)

	cDeviceEntry := C.blkid_evaluate_spec(cDevice, &cache)
	defer C.string_free(cDeviceEntry)
	deviceEntry := C.GoString(cDeviceEntry)

	log.Printf("blkid_evaluate_spec(%q, <cache>) = %q", mnt.Device, deviceEntry)

	cToken := C.CString(token)
	defer C.string_free(cToken)

	cValue := C.blkid_get_tag_value(cache, cToken, cDeviceEntry)
	defer C.string_free(cValue)
	value := C.GoString(cValue)

	log.Printf("blkid_get_tag_value(<cache>, %s, %s) = %s", token, deviceEntry, value)

	if value == "" {
		return "", errors.Wrapf(ErrMakeLink, "no %s", token)
	}
	return fmt.Sprintf("%s=%s", token, C.GoString(cValue)), nil
}

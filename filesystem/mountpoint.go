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
*/
import "C"

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// SupportedFilesystems is a map of the filesystems which support
	// filesystem-level encryption.
	SupportedFilesystems = map[string]bool{
		"ext4":  true,
		"f2fs":  true,
		"ubifs": true,
	}
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
		return ErrBadLoad
	}
	defer C.endmntent(fileHandle)

	// Load the device information from the default blkid cache
	if cache != nil {
		C.blkid_put_cache(cache)
	}
	if C.blkid_get_cache(&cache, nil) != 0 {
		return ErrBadLoad
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
			log.Print(err)
			continue
		}
		// We can only use mountpoints that are directories for fscrypt.
		if !isDir(mnt.Path) {
			continue
		}

		// Note this overrides the info if we have seen the mountpoint
		// earlier in the file. This is correct behavior because the
		// filesystems are listed in mount order.
		mountsByPath[mnt.Path] = &mnt

		// Use libblkid to get the device name
		cDeviceName := C.blkid_evaluate_spec(entry.mnt_fsname, &cache)
		defer C.string_free(cDeviceName)

		deviceName, err := cannonicalizePath(C.GoString(cDeviceName))

		// Only use real valid devices (unlike cgroups, tmpfs, ...)
		if err == nil && isDevice(deviceName) {
			mnt.Device = deviceName
			mountsByDevice[deviceName] = append(mountsByDevice[deviceName], &mnt)
		}
	}
}

// checkSupport returns an error if the specified mount does not support
// filesystem-level encryption.
func checkSupport(mount *Mount) error {
	if SupportedFilesystems[mount.Filesystem] {
		return nil
	}
	log.Printf("filesystem %s does not support filesystem encryption", mount.Filesystem)
	return ErrNoSupport
}

// AllSupportedFilesystems lists all the Mounts which could support filesystem
// encryption. This doesn't mean they necessarily do or that they are being used
// with fscrypt.
func AllSupportedFilesystems() (mounts []*Mount) {
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := getMountInfo(); err != nil {
		log.Print(err)
		return
	}

	for _, mount := range mountsByPath {
		if checkSupport(mount) == nil {
			mounts = append(mounts, mount)
		}
	}
	return
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
// is invalid, we cannot load the required mount data, or the filesystem does
// not support filesystem encryption. If a filesystem has been updated since the
// last call to one of the mount functions, run UpdateMountInfo to see changes.
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
			return mnt, checkSupport(mnt)
		}

		// Move to the parent directory unless we have reached the root.
		parent := filepath.Dir(path)
		if parent == path {
			return nil, ErrRootNotMount
		}
		path = parent
	}
}

// GetMount returns the Mount object with a matching mountpoint. An error is
// returned if the path is invalid, we cannot load the required mount data, or
// the filesystem does not support filesystem encryption. If a filesystem has
// been updated since the last call to one of the mount functions, run
// UpdateMountInfo to see changes.
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
		return mnt, checkSupport(mnt)
	}

	log.Printf("%q is not a filesystem mountpoint", mountpoint)
	return nil, ErrInvalidMount
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
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := getMountInfo(); err != nil {
		return nil, err
	}

	// Use blkid to get the device
	cLink := C.CString(link)
	defer C.string_free(cLink)
	cDeviceName := C.blkid_evaluate_spec(cLink, &cache)
	defer C.string_free(cDeviceName)

	deviceName, err := cannonicalizePath(C.GoString(cDeviceName))
	if err != nil {
		return nil, err
	}

	if mnts, ok := mountsByDevice[deviceName]; ok {
		return mnts, nil
	}

	log.Printf("link %q does not refer to a device", link)
	return nil, ErrNoLink
}

// makeLink returns a link of the form <token>=<value> where value is the tag
// value for the Mount's device according to libblkid. An error is returned if
// the device/token pair has no value.
func makeLink(mnt *Mount, token string) (string, error) {
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := getMountInfo(); err != nil {
		return "", err
	}

	cToken := C.CString(token)
	defer C.string_free(cToken)
	cDevice := C.CString(mnt.Device)
	defer C.string_free(cDevice)

	cValue := C.blkid_get_tag_value(cache, cToken, cDevice)
	if cValue == nil {
		log.Printf("filesystem at %q has no %s", mnt.Path, token)
		return "", ErrCannotLink
	}
	defer C.string_free(cValue)

	return fmt.Sprintf("%s=%s", token, C.GoString(cValue)), nil
}

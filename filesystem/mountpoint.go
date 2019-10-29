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
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

var (
	// This map holds data about the state of the system's filesystems.
	mountsByDevice map[DeviceNumber]*Mount
	// Used to make the mount functions thread safe
	mountMutex sync.Mutex
	// True if the maps have been successfully initialized.
	mountsInitialized bool
	// Supported tokens for filesystem links
	uuidToken = "UUID"
	// Location to perform UUID lookup
	uuidDirectory = "/dev/disk/by-uuid"
)

// Unescape octal-encoded escape sequences in a string from the mountinfo file.
// The kernel encodes the ' ', '\t', '\n', and '\\' bytes this way.  This
// function exactly inverts what the kernel does, including by preserving
// invalid UTF-8.
func unescapeString(str string) string {
	var sb strings.Builder
	for i := 0; i < len(str); i++ {
		b := str[i]
		if b == '\\' && i+3 < len(str) {
			if parsed, err := strconv.ParseInt(str[i+1:i+4], 8, 8); err == nil {
				b = uint8(parsed)
				i += 3
			}
		}
		sb.WriteByte(b)
	}
	return sb.String()
}

// We get the device name via the device number rather than use the mount source
// field directly.  This is necessary to handle a rootfs that was mounted via
// the kernel command line, since mountinfo always shows /dev/root for that.
// This assumes that the device nodes are in the standard location.
func getDeviceName(num DeviceNumber) string {
	linkPath := fmt.Sprintf("/sys/dev/block/%v", num)
	if target, err := os.Readlink(linkPath); err == nil {
		return fmt.Sprintf("/dev/%s", filepath.Base(target))
	}
	return ""
}

// Parse one line of /proc/self/mountinfo.
//
// The line contains the following space-separated fields:
//	[0] mount ID
//	[1] parent ID
//	[2] major:minor
//	[3] root
//	[4] mount point
//	[5] mount options
//	[6...n-1] optional field(s)
//	[n] separator
//	[n+1] filesystem type
//	[n+2] mount source
//	[n+3] super options
//
// For more details, see https://www.kernel.org/doc/Documentation/filesystems/proc.txt
func parseMountInfoLine(line string) *Mount {
	fields := strings.Split(line, " ")
	if len(fields) < 10 {
		return nil
	}

	// Count the optional fields.  In case new fields are appended later,
	// don't simply assume that n == len(fields) - 4.
	n := 6
	for fields[n] != "-" {
		n++
		if n >= len(fields) {
			return nil
		}
	}
	if n+3 >= len(fields) {
		return nil
	}

	var mnt *Mount = &Mount{}
	var err error
	mnt.DeviceNumber, err = newDeviceNumberFromString(fields[2])
	if err != nil {
		return nil
	}
	mnt.BindMnt = unescapeString(fields[3]) != "/"
	mnt.Path = unescapeString(fields[4])
	for _, opt := range strings.Split(fields[5], ",") {
		if opt == "ro" {
			mnt.ReadOnly = true
		}
	}
	mnt.FilesystemType = unescapeString(fields[n+1])
	mnt.Device = getDeviceName(mnt.DeviceNumber)
	return mnt
}

// loadMountInfo populates the Mount mappings by parsing /proc/self/mountinfo.
// It returns an error if the Mount mappings cannot be populated.
func loadMountInfo() error {
	if mountsInitialized {
		return nil
	}
	mountsByPath := make(map[string]*Mount)
	mountsByDevice = make(map[DeviceNumber]*Mount)

	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		mnt := parseMountInfoLine(line)
		if mnt == nil {
			log.Printf("ignoring invalid mountinfo line %q", line)
			continue
		}

		// We can only use mountpoints that are directories for fscrypt.
		if !isDir(mnt.Path) {
			log.Printf("ignoring mountpoint %q because it is not a directory", mnt.Path)
			continue
		}

		// Note this overrides the info if we have seen the mountpoint
		// earlier in the file. This is correct behavior because the
		// mountpoints are listed in mount order.
		mountsByPath[mnt.Path] = mnt
	}
	// fscrypt only really cares about the root directory of each
	// filesystem, because that's where the fscrypt metadata is stored.  So
	// keep just one Mount per filesystem, ignoring bind mounts.  Store that
	// Mount in mountsByDevice so that it can be found later from the device
	// number.  Also, prefer a read-write mount to a read-only one.
	//
	// If the filesystem has *only* bind mounts, store an explicit nil entry
	// so that we can show a useful error message later.
	for _, mnt := range mountsByPath {
		existingMnt, ok := mountsByDevice[mnt.DeviceNumber]
		if mnt.BindMnt {
			if !ok {
				mountsByDevice[mnt.DeviceNumber] = nil
			}
		} else if existingMnt == nil || (existingMnt.ReadOnly && !mnt.ReadOnly) {
			mountsByDevice[mnt.DeviceNumber] = mnt
		}
	}
	mountsInitialized = true
	return nil
}

func filesystemRootDirNotVisibleError(deviceNumber DeviceNumber) error {
	return errors.Errorf("root of filesystem on device %q (%v) is not visible in the current mount namespace",
		getDeviceName(deviceNumber), deviceNumber)
}

// AllFilesystems lists all non-bind Mounts on the current system ordered by
// path.  Use CheckSetup() to see if they are used with fscrypt.
func AllFilesystems() ([]*Mount, error) {
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := loadMountInfo(); err != nil {
		return nil, err
	}

	mounts := make([]*Mount, 0, len(mountsByDevice))
	for _, mount := range mountsByDevice {
		if mount != nil {
			mounts = append(mounts, mount)
		}
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
	return loadMountInfo()
}

// FindMount returns the main Mount object for the filesystem which contains the
// file at the specified path. An error is returned if the path is invalid or if
// we cannot load the required mount data. If a mount has been updated since the
// last call to one of the mount functions, run UpdateMountInfo to see changes.
func FindMount(path string) (*Mount, error) {
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := loadMountInfo(); err != nil {
		return nil, err
	}
	deviceNumber, err := getNumberOfContainingDevice(path)
	if err != nil {
		return nil, err
	}
	mnt, ok := mountsByDevice[deviceNumber]
	if !ok {
		return nil, errors.Errorf("couldn't find mountpoint containing %q", path)
	}
	if mnt == nil {
		return nil, filesystemRootDirNotVisibleError(deviceNumber)
	}
	return mnt, nil
}

// GetMount is like FindMount, except GetMount also returns an error if the path
// isn't the root directory of a filesystem.  For example, if a filesystem is
// mounted at "/mnt" and the file "/mnt/a" exists, FindMount("/mnt/a") will
// succeed whereas GetMount("/mnt/a") will fail.
func GetMount(mountpoint string) (*Mount, error) {
	mnt, err := FindMount(mountpoint)
	if err != nil {
		return nil, errors.Wrap(ErrNotAMountpoint, mountpoint)
	}
	// Check whether 'mountpoint' is the root directory of the filesystem,
	// i.e. is the same directory as 'mnt.Path'.  Use os.SameFile() (i.e.,
	// compare inode numbers) rather than compare canonical paths, since the
	// filesystem might be fully mounted in multiple places.
	fi1, err := os.Stat(mountpoint)
	if err != nil {
		return nil, err
	}
	fi2, err := os.Stat(mnt.Path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(fi1, fi2) {
		return nil, errors.Wrap(ErrNotAMountpoint, mountpoint)
	}
	return mnt, nil
}

// getMountsFromLink returns the Mount object which matches the provided link.
// This link is formatted as a tag (e.g. <token>=<value>) similar to how they
// appear in "/etc/fstab". Currently, only "UUID" tokens are supported. An error
// is returned if the link is invalid or we cannot load the required mount data.
// If a mount has been updated since the last call to one of the mount
// functions, run UpdateMountInfo to see the change.
func getMountFromLink(link string) (*Mount, error) {
	// Parse the link
	linkComponents := strings.Split(link, "=")
	if len(linkComponents) != 2 {
		return nil, errors.Wrapf(ErrFollowLink, "link %q format is invalid", link)
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
	deviceNumber, err := getDeviceNumber(searchPath)
	if err != nil {
		return nil, errors.Wrapf(ErrFollowLink, "no device with UUID %q", value)
	}

	// Lookup mountpoints for device in global store
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := loadMountInfo(); err != nil {
		return nil, err
	}
	mnt, ok := mountsByDevice[deviceNumber]
	if !ok {
		devicePath, _ := canonicalizePath(searchPath)
		return nil, errors.Wrapf(ErrFollowLink, "no mounts for device %q (%v)",
			devicePath, deviceNumber)
	}
	if mnt == nil {
		return nil, filesystemRootDirNotVisibleError(deviceNumber)
	}
	return mnt, nil
}

// makeLink returns a link of the form <token>=<value> where value is the tag
// value for the Mount's device. Currently, only "UUID" tokens are supported. An
// error is returned if the mount has no device, or no UUID.
func makeLink(mnt *Mount, token string) (string, error) {
	if token != uuidToken {
		return "", errors.Wrapf(ErrMakeLink, "token type %q not supported", token)
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
		deviceNumber, err := getDeviceNumber(filepath.Join(uuidDirectory, uuid))
		if err != nil {
			log.Print(err)
			continue
		}
		if mnt.DeviceNumber == deviceNumber {
			return fmt.Sprintf("%s=%s", uuidToken, uuid), nil
		}
	}
	return "", errors.Wrapf(ErrMakeLink, "device %q (%v) has no UUID",
		mnt.Device, mnt.DeviceNumber)
}

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
	"io"
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
	//
	// It only contains one Mount per filesystem, even if there are
	// additional bind mounts, since we want to store fscrypt metadata in
	// only one place per filesystem.  If it is ambiguous which Mount should
	// be used, an explicit nil entry is stored.
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
	mnt.Subtree = unescapeString(fields[3])
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

type mountpointTreeNode struct {
	mount    *Mount
	parent   *mountpointTreeNode
	children []*mountpointTreeNode
}

func addUncontainedSubtreesRecursive(dst map[string]bool,
	node *mountpointTreeNode, allUncontainedSubtrees map[string]bool) {
	if allUncontainedSubtrees[node.mount.Subtree] {
		dst[node.mount.Subtree] = true
	}
	for _, child := range node.children {
		addUncontainedSubtreesRecursive(dst, child, allUncontainedSubtrees)
	}
}

// findMainMount finds the "main" Mount of a filesystem.  The "main" Mount is
// where the filesystem's fscrypt metadata is stored.
//
// Normally, there is just one Mount and it's of the entire filesystem
// (mnt.Subtree == "/").  But in general, the filesystem might be mounted in
// multiple places, including "bind mounts" where mnt.Subtree != "/".  Also, the
// filesystem might have a combination of read-write and read-only mounts.
//
// To handle most cases, we could just choose a mount with mnt.Subtree == "/",
// preferably a read-write mount.  However, that doesn't work in containers
// where the "/" subtree might not be mounted.  Here's a real-world example:
//
//              mnt.Subtree               mnt.Path
//              -----------               --------
//              /var/lib/lxc/base/rootfs  /
//              /var/cache/pacman/pkg     /var/cache/pacman/pkg
//              /srv/repo/x86_64          /srv/http/x86_64
//
// In this case, all mnt.Subtree are independent.  To handle this case, we must
// choose the Mount whose mnt.Path contains the others, i.e. the first one.
// Note: the fscrypt metadata won't be usable from outside the container since
// it won't be at the real root of the filesystem, but that may be acceptable.
//
// However, we can't look *only* at mnt.Path, since in some cases mnt.Subtree is
// needed to correctly handle bind mounts.  For example, in the following case,
// the first Mount should be chosen:
//
//              mnt.Subtree               mnt.Path
//              -----------               --------
//              /foo                      /foo
//              /foo/dir                  /dir
//
// To solve this, we divide the mounts into non-overlapping trees of mnt.Path.
// Then, we choose one of these trees which contains (exactly or via path
// prefix) *all* mnt.Subtree.  We then return the root of this tree.  In both
// the above examples, this algorithm returns the first Mount.
func findMainMount(filesystemMounts []*Mount, lookuppath string) *Mount {
	metadataPath := ""
	// Index this filesystem's mounts by path.  Note: paths are unique here,
	// since non-last mounts were already excluded earlier.
	//
	// Also build the set of all mounted subtrees.
	mountsByPath := make(map[string]*mountpointTreeNode)
	allSubtrees := make(map[string]bool)
	for _, mnt := range filesystemMounts {
		mountsByPath[mnt.Path] = &mountpointTreeNode{mount: mnt}
		allSubtrees[mnt.Subtree] = true
	}

	// Divide the mounts into non-overlapping trees of mountpoints.
	for path, mntNode := range mountsByPath {
		for path != "/" && mntNode.parent == nil {
			path = filepath.Dir(path)
			if parent := mountsByPath[path]; parent != nil {
				mntNode.parent = parent
				parent.children = append(parent.children, mntNode)
			}
		}
	}

	// Build the set of mounted subtrees that aren't contained in any other
	// mounted subtree.
	allUncontainedSubtrees := make(map[string]bool)
	for subtree := range allSubtrees {
		contained := false
		for t := subtree; t != "/" && !contained; {
			t = filepath.Dir(t)
			contained = allSubtrees[t]
		}
		if !contained {
			allUncontainedSubtrees[subtree] = true
		}
	}

	// Select the root of a mountpoint tree whose mounted subtrees contain
	// *all* mounted subtrees.  Equivalently, select a mountpoint tree in
	// which every uncontained subtree is mounted.
	var mainMount *Mount
	for _, mntNode := range mountsByPath {
		mnt := mntNode.mount
		if mntNode.parent != nil {
			continue
		}
		uncontainedSubtrees := make(map[string]bool)
		addUncontainedSubtreesRecursive(uncontainedSubtrees, mntNode, allUncontainedSubtrees)
		if len(uncontainedSubtrees) != len(allUncontainedSubtrees) {
			if mnt.Subtree == "/"+baseDirName && !allSubtrees["/"] {
				metadataPath = mnt.Path
			} else if len(lookuppath) > 0 &&
				(mainMount == nil || mainMount.ReadOnly ||
					(strings.HasPrefix(lookuppath, mnt.Path) &&
						(len(lookuppath) == len(mnt.Path) || lookuppath[len(mnt.Path)] == '/'))) {
				mainMount = mnt
			}
			continue
		}
		// If there's more than one eligible mount, they should have the
		// same Subtree.  Otherwise it's ambiguous which one to use.
		if mainMount != nil && mainMount.Subtree != mnt.Subtree {
			log.Printf("Unsupported case: %q (%v) has multiple non-overlapping mounts. This filesystem will be ignored!",
				mnt.Device, mnt.DeviceNumber)
			return nil
		}
		// Prefer a read-write mount to a read-only one.
		if filepath.Base(mnt.Path) != baseDirName &&
			(mainMount == nil || mainMount.ReadOnly ||
				(len(lookuppath) > 0 && strings.HasPrefix(lookuppath, mnt.Path) &&
					(len(lookuppath) == len(mnt.Path) || lookuppath[len(mnt.Path)] == '/'))) {
			mainMount = mnt
		}

		if filepath.Base(mnt.Path) == baseDirName {
			metadataPath = mnt.Path
		}
	}
	if mainMount != nil {
		mainMount.MetadataPath = metadataPath
	}
	return mainMount
}

// This is separate from loadMountInfo() only for unit testing.
func readMountInfo(r io.Reader, path string) error {
	mountsByPath := make(map[string]*Mount)
	mountsByDevice = make(map[DeviceNumber]*Mount)

	scanner := bufio.NewScanner(r)
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
	// For each filesystem, choose a "main" Mount and discard any additional
	// bind mounts.  fscrypt only cares about the main Mount, since it's
	// where the fscrypt metadata is stored.  Store all main Mounts in
	// mountsByDevice so that they can be found by device number later.
	allMountsByDevice := make(map[DeviceNumber][]*Mount)
	for _, mnt := range mountsByPath {
		allMountsByDevice[mnt.DeviceNumber] =
			append(allMountsByDevice[mnt.DeviceNumber], mnt)
	}
	for deviceNumber, filesystemMounts := range allMountsByDevice {
		mountsByDevice[deviceNumber] = findMainMount(filesystemMounts, path)
	}
	return nil
}

// loadMountInfo populates the Mount mappings by parsing /proc/self/mountinfo.
// It returns an error if the Mount mappings cannot be populated.
func loadMountInfo(path string) error {
	if !mountsInitialized {
		file, err := os.Open("/proc/self/mountinfo")
		if err != nil {
			return err
		}
		defer file.Close()
		if err := readMountInfo(file, path); err != nil {
			return err
		}
		mountsInitialized = true
	}
	return nil
}

func filesystemLacksMainMountError(deviceNumber DeviceNumber) error {
	return errors.Errorf("Device %q (%v) lacks a \"main\" mountpoint in the current mount namespace, so it's ambiguous where to store the fscrypt metadata.",
		getDeviceName(deviceNumber), deviceNumber)
}

// AllFilesystems lists all mounted filesystems ordered by path to their "main"
// Mount.  Use CheckSetup() to see if they are set up for use with fscrypt.
func AllFilesystems() ([]*Mount, error) {
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := loadMountInfo(""); err != nil {
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
	return loadMountInfo("")
}

// FindMount returns the main Mount object for the filesystem which contains the
// file at the specified path. An error is returned if the path is invalid or if
// we cannot load the required mount data. If a mount has been updated since the
// last call to one of the mount functions, run UpdateMountInfo to see changes.
func FindMount(path string) (*Mount, error) {
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := loadMountInfo(path); err != nil {
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
		return nil, filesystemLacksMainMountError(deviceNumber)
	}
	return mnt, nil
}

// GetMount is like FindMount, except GetMount also returns an error if the path
// doesn't name the same file as the filesystem's "main" Mount.  For example, if
// a filesystem is fully mounted at "/mnt" and if "/mnt/a" exists, then
// FindMount("/mnt/a") will succeed whereas GetMount("/mnt/a") will fail.  This
// is true even if "/mnt/a" is a bind mount of part of the same filesystem.
func GetMount(mountpoint string) (*Mount, error) {
	mnt, err := FindMount(mountpoint)
	if err != nil {
		return nil, &ErrNotAMountpoint{mountpoint}
	}
	// Check whether 'mountpoint' names the same directory as 'mnt.Path'.
	// Use os.SameFile() (i.e., compare inode numbers) rather than compare
	// canonical paths, since filesystems may be mounted in multiple places.
	fi1, err := os.Stat(mountpoint)
	if err != nil {
		return nil, err
	}
	fi2, err := os.Stat(mnt.Path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(fi1, fi2) {
		return nil, &ErrNotAMountpoint{mountpoint}
	}
	return mnt, nil
}

// getMountFromLink returns the Mount object which matches the provided link.
// This link is formatted as a tag (e.g. <token>=<value>) similar to how they
// appear in "/etc/fstab". Currently, only "UUID" tokens are supported. An error
// is returned if the link is invalid or we cannot load the required mount data.
// If a mount has been updated since the last call to one of the mount
// functions, run UpdateMountInfo to see the change.
func getMountFromLink(link string) (*Mount, error) {
	// Parse the link
	link = strings.TrimSpace(link)
	linkComponents := strings.Split(link, "=")
	if len(linkComponents) != 2 {
		return nil, &ErrFollowLink{link, errors.New("invalid link format")}
	}
	token := linkComponents[0]
	value := linkComponents[1]
	if token != uuidToken {
		return nil, &ErrFollowLink{link, errors.Errorf("token type %q not supported", token)}
	}

	// See if UUID points to an existing device
	searchPath := filepath.Join(uuidDirectory, value)
	if filepath.Base(searchPath) != value {
		return nil, &ErrFollowLink{link, errors.Errorf("invalid UUID format %q", value)}
	}
	deviceNumber, err := getDeviceNumber(searchPath)
	if err != nil {
		return nil, &ErrFollowLink{link, errors.Errorf("no device with UUID %s", value)}
	}

	// Lookup mountpoints for device in global store
	mountMutex.Lock()
	defer mountMutex.Unlock()
	if err := loadMountInfo(searchPath); err != nil {
		return nil, err
	}
	mnt, ok := mountsByDevice[deviceNumber]
	if !ok {
		return nil, &ErrFollowLink{link, errors.Errorf("no mounts for device %q (%v)",
			getDeviceName(deviceNumber), deviceNumber)}
	}
	if mnt == nil {
		return nil, &ErrFollowLink{link, filesystemLacksMainMountError(deviceNumber)}
	}
	return mnt, nil
}

// makeLink returns a link of the form <token>=<value> where value is the tag
// value for the Mount's device. Currently, only "UUID" tokens are supported. An
// error is returned if the mount has no device, or no UUID.
func makeLink(mnt *Mount, token string) (string, error) {
	if token != uuidToken {
		return "", &ErrMakeLink{mnt, errors.Errorf("token type %q not supported", token)}
	}

	dirContents, err := ioutil.ReadDir(uuidDirectory)
	if err != nil {
		return "", &ErrMakeLink{mnt, err}
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
	return "", &ErrMakeLink{mnt, errors.Errorf("cannot determine UUID of device %q (%v)",
		mnt.Device, mnt.DeviceNumber)}
}

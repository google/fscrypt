/*
 * mountpoint_test.go - Tests for reading information about all mountpoints.
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

// Note: these tests assume the existence of some well-known directories and
// devices: /mnt, /home, /tmp, and /dev/loop0.  This is because the mountpoint
// loading code only retains mountpoints on valid directories, and only retains
// device names for valid device nodes.

package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMountInfo(t *testing.T) {
	if err := UpdateMountInfo(); err != nil {
		t.Error(err)
	}
}

// Lock the mount maps so that concurrent tests don't interfere with each other.
func beginLoadMountInfoTest() {
	mountMutex.Lock()
}

func endLoadMountInfoTest() {
	// Invalidate the fake mount information in case a test runs later which
	// needs the real mount information.
	mountsInitialized = false
	mountMutex.Unlock()
}

func loadMountInfoFromString(str string) {
	readMountInfo(strings.NewReader(str))
}

func mountForDevice(deviceNumberStr string) *Mount {
	deviceNumber, _ := newDeviceNumberFromString(deviceNumberStr)
	return mountsByDevice[deviceNumber]
}

// Test basic loading of a single mountpoint.
func TestLoadMountInfoBasic(t *testing.T) {
	var mountinfo = `
15 0 259:3 / / rw,relatime shared:1 - ext4 /dev/root rw,data=ordered
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	if len(mountsByDevice) != 1 {
		t.Error("Loaded wrong number of mounts")
	}
	mnt := mountForDevice("259:3")
	if mnt == nil {
		t.Fatal("Failed to load mount")
	}
	if mnt.Path != "/" {
		t.Error("Wrong path")
	}
	if mnt.FilesystemType != "ext4" {
		t.Error("Wrong filesystem type")
	}
	if mnt.DeviceNumber.String() != "259:3" {
		t.Error("Wrong device number")
	}
	if mnt.Subtree != "/" {
		t.Error("Wrong subtree")
	}
	if mnt.ReadOnly {
		t.Error("Wrong readonly flag")
	}
	if len(mountsByPath) != 1 {
		t.Error("mountsByPath doesn't contain exactly one entry")
	}
	if mountsByPath[mnt.Path] != mnt {
		t.Error("mountsByPath doesn't contain the correct entry")
	}
}

// Test that Mount.Device is set to the mountpoint's source device if
// applicable, otherwise it is set to the empty string.
func TestLoadSourceDevice(t *testing.T) {
	var mountinfo = `
15 0 7:0 / / rw shared:1 - foo /dev/loop0 rw,data=ordered
31 15 0:27 / /tmp rw,nosuid,nodev shared:17 - tmpfs tmpfs rw
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	mnt := mountForDevice("7:0")
	if mnt.Device != "/dev/loop0" {
		t.Error("mnt.Device wasn't set to source device")
	}
	mnt = mountForDevice("0:27")
	if mnt.Device != "" {
		t.Error("mnt.Device wasn't set to empty string for an invalid device")
	}
}

// Test that non-directory mounts are ignored.
func TestNondirectoryMountsIgnored(t *testing.T) {
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	file, err := os.CreateTemp("", "fscrypt_regfile")
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	defer os.Remove(file.Name())

	mountinfo := fmt.Sprintf("15 0 259:3 /foo %s rw,relatime shared:1 - ext4 /dev/root rw", file.Name())
	loadMountInfoFromString(mountinfo)
	if len(mountsByDevice) != 0 {
		t.Error("Non-directory mount wasn't ignored")
	}
}

// Test that when multiple mounts are on one directory, the last is the one
// which is kept.
func TestNonLatestMountsIgnored(t *testing.T) {
	mountinfo := `
15 0 259:3 / / rw shared:1 - ext4 /dev/root rw
15 0 259:3 / / rw shared:1 - f2fs /dev/root rw
15 0 259:3 / / rw shared:1 - ubifs /dev/root rw
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	mnt := mountForDevice("259:3")
	if mnt.FilesystemType != "ubifs" {
		t.Error("Last mount didn't supersede previous ones")
	}
}

// Test that escape sequences in the mountinfo file are unescaped correctly.
func TestLoadMountWithSpecialCharacters(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "fscrypt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	tempDir, err = filepath.Abs(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	mountpoint := filepath.Join(tempDir, "/My Directory\t\n\\")
	if err := os.Mkdir(mountpoint, 0700); err != nil {
		t.Fatal(err)
	}
	mountinfo := fmt.Sprintf("15 0 259:3 / %s/My\\040Directory\\011\\012\\134 rw shared:1 - ext4 /dev/root rw", tempDir)

	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	mnt := mountForDevice("259:3")
	if mnt.Path != mountpoint {
		t.Fatal("Wrong mountpoint")
	}
}

// Tests the EscapeString() and unescapeString() functions.
func TestStringEscaping(t *testing.T) {
	charsNeedEscaping := " \t\n\\"
	charsDontNeedEscaping := "ABCDEF\u2603\xff\xff\v"

	orig := charsNeedEscaping + charsDontNeedEscaping
	escaped := `\040\011\012\134` + charsDontNeedEscaping
	if EscapeString(orig) != escaped {
		t.Fatal("EscapeString gave wrong result")
	}
	if unescapeString(escaped) != orig {
		t.Fatal("unescapeString gave wrong result")
	}
}

// Test parsing some invalid mountinfo lines.
func TestLoadBadMountInfo(t *testing.T) {
	mountinfos := []string{"a",
		"a a a a a a a a a a a a a a a",
		"a a a a a a a a a a a a - a a",
		"15 0 BAD:3 / / rw,relatime shared:1 - ext4 /dev/root rw,data=ordered"}
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	for _, mountinfo := range mountinfos {
		loadMountInfoFromString(mountinfo)
		if len(mountsByDevice) != 0 {
			t.Error("Loaded mount from invalid mountinfo line")
		}
	}
}

// Test that the ReadOnly flag is set if the mount is readonly, even if the
// filesystem is read-write.
func TestLoadReadOnlyMount(t *testing.T) {
	mountinfo := `
222 15 259:3 / /mnt ro,relatime shared:1 - ext4 /dev/root rw,data=ordered
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	mnt := mountForDevice("259:3")
	if !mnt.ReadOnly {
		t.Error("Wrong readonly flag")
	}
}

// Test that a read-write mount is preferred over a read-only mount.
func TestReadWriteMountIsPreferredOverReadOnlyMount(t *testing.T) {
	mountinfo := `
222 15 259:3 / /home ro shared:1 - ext4 /dev/root rw
222 15 259:3 / /mnt rw shared:1 - ext4 /dev/root rw
222 15 259:3 / /tmp ro shared:1 - ext4 /dev/root rw
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	mnt := mountForDevice("259:3")
	if mnt.Path != "/mnt" {
		t.Error("Wrong mount was chosen")
	}
}

// Test that a mount of the full filesystem is preferred over mounts of non-root
// subtrees, given independent mountpoints.
func TestRootSubtreeIsPreferred(t *testing.T) {
	mountinfo := `
222 15 259:3 /subtree1 /home rw shared:1 - ext4 /dev/root rw
222 15 259:3 / /mnt rw shared:1 - ext4 /dev/root rw
222 15 259:3 /subtree2 /tmp rw shared:1 - ext4 /dev/root rw
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	mnt := mountForDevice("259:3")
	if mnt.Subtree != "/" {
		t.Error("Wrong mount was chosen")
	}
}

// Test that a mount that is not of the full filesystem but still contains all
// other mounted subtrees is preferred, given independent mountpoints.
func TestHighestSubtreeIsPreferred(t *testing.T) {
	mountinfo := `
222 15 259:3 /foo/bar /mnt rw shared:1 - ext4 /dev/root rw
222 15 259:3 /foo /tmp rw shared:1 - ext4 /dev/root rw
222 15 259:3 /foo/baz /home rw shared:1 - ext4 /dev/root rw
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	deviceNumber, _ := newDeviceNumberFromString("259:3")
	mnt := mountsByDevice[deviceNumber]
	if mnt.Subtree != "/foo" {
		t.Error("Wrong mount was chosen")
	}
}

// Test that mountpoint "/" is preferred, given independent subtrees.
func TestRootMountpointIsPreferred(t *testing.T) {
	mountinfo := `
222 15 259:3 /var/cache/pacman/pkg /mnt rw shared:1 - ext4 /dev/root rw
222 15 259:3 /var/lib/lxc/base/rootfs / rw shared:1 - ext4 /dev/root rw
222 15 259:3 /srv/repo/x86_64 /home rw shared:1 - ext4 /dev/root rw
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	deviceNumber, _ := newDeviceNumberFromString("259:3")
	mnt := mountsByDevice[deviceNumber]
	if mnt.Subtree != "/var/lib/lxc/base/rootfs" {
		t.Error("Wrong mount was chosen")
	}
}

// Test that a mountpoint that is not "/" but still contains all other
// mountpoints is preferred, given independent subtrees.
func TestHighestMountpointIsPreferred(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "fscrypt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	tempDir, err = filepath.Abs(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tempDir+"/a/b", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tempDir+"/a/c", 0700); err != nil {
		t.Fatal(err)
	}
	mountinfo := fmt.Sprintf(`
222 15 259:3 /0 %s rw shared:1 - ext4 /dev/root rw
222 15 259:3 /1 %s rw shared:1 - ext4 /dev/root rw
222 15 259:3 /2 %s rw shared:1 - ext4 /dev/root rw
`, tempDir+"/a/b", tempDir+"/a", tempDir+"/a/c")

	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	deviceNumber, _ := newDeviceNumberFromString("259:3")
	mnt := mountsByDevice[deviceNumber]
	if mnt.Subtree != "/1" {
		t.Error("Wrong mount was chosen")
	}
}

// Test that if some subtrees are contained in other subtrees, *and* some
// mountpoints are contained in other mountpoints, the chosen Mount is the root
// of a tree of mountpoints whose mounted subtrees contain all mounted subtrees.
func TestLoadContainedSubtreesAndMountpoints(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "fscrypt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	tempDir, err = filepath.Abs(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tempDir+"/a/b", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tempDir+"/a/c", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tempDir+"/d", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tempDir+"/e", 0700); err != nil {
		t.Fatal(err)
	}
	// The first three mounts form a tree of mountpoints.  The rest have
	// independent mountpoints but have mounted subtrees contained in the
	// mounted subtrees of the first mountpoint tree.
	mountinfo := fmt.Sprintf(`
222 15 259:3 /0 %s rw shared:1 - ext4 /dev/root rw
222 15 259:3 /1 %s rw shared:1 - ext4 /dev/root rw
222 15 259:3 /2 %s rw shared:1 - ext4 /dev/root rw
222 15 259:3 /1/3 %s rw shared:1 - ext4 /dev/root rw
222 15 259:3 /2/4 %s rw shared:1 - ext4 /dev/root rw
`, tempDir+"/a/b", tempDir+"/a", tempDir+"/a/c",
		tempDir+"/d", tempDir+"/e")

	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	deviceNumber, _ := newDeviceNumberFromString("259:3")
	mnt := mountsByDevice[deviceNumber]
	if mnt.Subtree != "/1" {
		t.Error("Wrong mount was chosen")
	}
}

// Test loading mounts with independent subtrees *and* independent mountpoints.
// This case is ambiguous, so an explicit nil entry should be stored.
func TestLoadAmbiguousMounts(t *testing.T) {
	mountinfo := `
222 15 259:3 /foo /mnt rw shared:1 - ext4 /dev/root rw
222 15 259:3 /bar /tmp rw shared:1 - ext4 /dev/root rw
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	deviceNumber, _ := newDeviceNumberFromString("259:3")
	mnt, ok := mountsByDevice[deviceNumber]
	if !ok {
		t.Error("Entry should exist")
	}
	if mnt != nil {
		t.Error("Entry should be nil")
	}
}

// Test making a filesystem link and following it, and test that leading and
// trailing whitespace in the link is ignored.
func TestGetMountFromLink(t *testing.T) {
	mnt, err := getTestMount(t)
	if err != nil {
		t.Skip(err)
	}
	link, err := makeLink(mnt)
	if err != nil {
		t.Fatal(err)
	}
	linkedMnt, err := getMountFromLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if linkedMnt != mnt {
		t.Fatal("Link doesn't point to the same Mount")
	}
	if linkedMnt, err = getMountFromLink(link + "\n"); err != nil {
		t.Fatal(err)
	}
	if linkedMnt != mnt {
		t.Fatal("Link doesn't point to the same Mount")
	}
	if linkedMnt, err = getMountFromLink("  " + link + "  \r\n"); err != nil {
		t.Fatal(err)
	}
	if linkedMnt != mnt {
		t.Fatal("Link doesn't point to the same Mount")
	}
}

// Test that makeLink() is including the expected information in links.
func TestMakeLink(t *testing.T) {
	mnt, err := getTestMount(t)
	if err != nil {
		t.Skip(err)
	}
	link, err := makeLink(mnt)
	if err != nil {
		t.Fatal(err)
	}

	// Normally, both UUID and PATH should be included.
	if !strings.Contains(link, "UUID=") {
		t.Fatal("Link doesn't contain UUID")
	}
	if !strings.Contains(link, "PATH=") {
		t.Fatal("Link doesn't contain PATH")
	}

	// Without a valid device number, only PATH should be included.
	mntCopy := *mnt
	mntCopy.DeviceNumber = 0
	link, err = makeLink(&mntCopy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(link, "UUID=") {
		t.Fatal("Link shouldn't contain UUID")
	}
	if !strings.Contains(link, "PATH=") {
		t.Fatal("Link doesn't contain PATH")
	}
}

// Test that old filesystem links that contain a UUID only still work.
func TestGetMountFromLegacyLink(t *testing.T) {
	mnt, err := getTestMount(t)
	if err != nil {
		t.Skip(err)
	}
	uuid, err := mnt.getFilesystemUUID()
	if uuid == "" || err != nil {
		t.Fatal("Can't get UUID of test filesystem")
	}

	link := fmt.Sprintf("UUID=%s", uuid)
	linkedMnt, err := getMountFromLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if linkedMnt != mnt {
		t.Fatal("Link doesn't point to the same Mount")
	}
}

// Test that if the UUID in a filesystem link doesn't work, then the PATH is
// used instead, and vice versa.
func TestGetMountFromLinkFallback(t *testing.T) {
	mnt, err := getTestMount(t)
	if err != nil {
		t.Skip(err)
	}
	badUUID := "00000000-0000-0000-0000-000000000000"
	badPath := "/NONEXISTENT_MOUNT"
	goodUUID, err := mnt.getFilesystemUUID()
	if goodUUID == "" || err != nil {
		t.Fatal("Can't get UUID of test filesystem")
	}

	// only PATH valid (should succeed)
	link := fmt.Sprintf("UUID=%s\nPATH=%s\n", badUUID, mnt.Path)
	linkedMnt, err := getMountFromLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if linkedMnt != mnt {
		t.Fatal("Link doesn't point to the same Mount")
	}

	// only PATH given at all (should succeed)
	link = fmt.Sprintf("PATH=%s\n", mnt.Path)
	linkedMnt, err = getMountFromLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if linkedMnt != mnt {
		t.Fatal("Link doesn't point to the same Mount")
	}

	// only UUID valid (should succeed)
	link = fmt.Sprintf("UUID=%s\nPATH=%s\n", goodUUID, badPath)
	if linkedMnt, err = getMountFromLink(link); err != nil {
		t.Fatal(err)
	}
	if linkedMnt != mnt {
		t.Fatal("Link doesn't point to the same Mount")
	}

	// neither valid (should fail)
	link = fmt.Sprintf("UUID=%s\nPATH=%s\n", badUUID, badPath)
	linkedMnt, err = getMountFromLink(link)
	if linkedMnt != nil || err == nil {
		t.Fatal("Following a bad link succeeded")
	}
}

// Benchmarks how long it takes to update the mountpoint data
func BenchmarkLoadFirst(b *testing.B) {
	for n := 0; n < b.N; n++ {
		err := UpdateMountInfo()
		if err != nil {
			b.Fatal(err)
		}
	}
}

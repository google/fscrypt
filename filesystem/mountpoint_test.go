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
	"io/ioutil"
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
	if mnt.BindMnt {
		t.Error("Wrong bind mount flag")
	}
	if mnt.ReadOnly {
		t.Error("Wrong readonly flag")
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
	file, err := ioutil.TempFile("", "fscrypt_regfile")
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
	tempDir, err := ioutil.TempDir("", "fscrypt")
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

// Test that a mount of the full filesystem is preferred over a bind mount.
func TestFullMountIsPreferredOverBindMount(t *testing.T) {
	mountinfo := `
222 15 259:3 /subtree1 /home rw shared:1 - ext4 /dev/root rw
222 15 259:3 / /mnt rw shared:1 - ext4 /dev/root rw
222 15 259:3 /subtree2 /tmp rw shared:1 - ext4 /dev/root rw
`
	beginLoadMountInfoTest()
	defer endLoadMountInfoTest()
	loadMountInfoFromString(mountinfo)
	mnt := mountForDevice("259:3")
	if mnt.Path != "/mnt" {
		t.Error("Wrong mount was chosen")
	}
}

// Test that if a filesystem only has bind mounts, a nil mountsByDevice entry is
// created.
func TestLoadOnlyBindMounts(t *testing.T) {
	mountinfo := `
222 15 259:3 /foo /mnt ro,relatime shared:1 - ext4 /dev/root rw,data=ordered
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

// Test making a filesystem link (i.e. "UUID=...") and following it, and test
// that leading and trailing whitespace in the link is ignored.
func TestGetMountFromLink(t *testing.T) {
	mnt, err := getTestMount(t)
	if err != nil {
		t.Skip(err)
	}
	link, err := makeLink(mnt, uuidToken)
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

// Benchmarks how long it takes to update the mountpoint data
func BenchmarkLoadFirst(b *testing.B) {
	for n := 0; n < b.N; n++ {
		err := UpdateMountInfo()
		if err != nil {
			b.Fatal(err)
		}
	}
}

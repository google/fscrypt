/*
 * filesystem_test.go - Tests for reading/writing metadata to disk.
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
	"os/user"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/golang/protobuf/proto"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/util"
)

var (
	fakeProtectorKey, _    = crypto.NewRandomKey(metadata.InternalKeyLen)
	fakePolicyKey, _       = crypto.NewRandomKey(metadata.PolicyKeyLen)
	wrappedProtectorKey, _ = crypto.Wrap(fakeProtectorKey, fakeProtectorKey)
	wrappedPolicyKey, _    = crypto.Wrap(fakeProtectorKey, fakePolicyKey)
)

// Gets the mount corresponding to the integration test path.
func getTestMount(t *testing.T) (*Mount, error) {
	mountpoint, err := util.TestRoot()
	if err != nil {
		t.Skip(err)
	}
	return GetMount(mountpoint)
}

func getFakeProtector() *metadata.ProtectorData {
	return &metadata.ProtectorData{
		ProtectorDescriptor: "fedcba9876543210",
		Name:                "goodProtector",
		Source:              metadata.SourceType_raw_key,
		WrappedKey:          wrappedProtectorKey,
	}
}

func getFakeLoginProtector(uid int64) *metadata.ProtectorData {
	protector := getFakeProtector()
	protector.Source = metadata.SourceType_pam_passphrase
	protector.Uid = uid
	protector.Costs = &metadata.HashingCosts{
		Time:        1,
		Memory:      1 << 8,
		Parallelism: 1,
	}
	protector.Salt = make([]byte, 16)
	return protector
}

func getFakePolicy() *metadata.PolicyData {
	return &metadata.PolicyData{
		KeyDescriptor: "0123456789abcdef",
		Options:       metadata.DefaultOptions,
		WrappedPolicyKeys: []*metadata.WrappedPolicyKey{
			{
				ProtectorDescriptor: "fedcba9876543210",
				WrappedKey:          wrappedPolicyKey,
			},
		},
	}
}

// Gets the mount and sets it up
func getSetupMount(t *testing.T) (*Mount, error) {
	mnt, err := getTestMount(t)
	if err != nil {
		return nil, err
	}
	return mnt, mnt.Setup(WorldWritable)
}

// Tests that the setup works and creates the correct files
func TestSetup(t *testing.T) {
	mnt, err := getSetupMount(t)
	if err != nil {
		t.Fatal(err)
	}

	if err := mnt.CheckSetup(nil); err != nil {
		t.Error(err)
	}

	os.RemoveAll(mnt.BaseDir())
}

// Tests that we can remove all of the metadata
func TestRemoveAllMetadata(t *testing.T) {
	mnt, err := getSetupMount(t)
	if err != nil {
		t.Fatal(err)
	}

	if err = mnt.RemoveAllMetadata(); err != nil {
		t.Fatal(err)
	}

	if isDir(mnt.BaseDir()) {
		t.Error("metadata was not removed")
	}
}

// isSymlink returns true if the path exists and is that of a symlink.
func isSymlink(path string) bool {
	info, err := loggedLstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

// Test that when MOUNTPOINT/.fscrypt is a pre-created symlink, fscrypt will
// create/delete the metadata at the location pointed to by the symlink.
//
// This is a helper function that is called twice: once to test an absolute
// symlink and once to test a relative symlink.
func testSetupWithSymlink(t *testing.T, mnt *Mount, symlinkTarget string, realDir string) {
	rawBaseDir := filepath.Join(mnt.Path, baseDirName)
	if err := os.Symlink(symlinkTarget, rawBaseDir); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(rawBaseDir)

	if err := mnt.Setup(WorldWritable); err != nil {
		t.Fatal(err)
	}
	defer mnt.RemoveAllMetadata()
	if err := mnt.CheckSetup(nil); err != nil {
		t.Fatal(err)
	}
	if !isSymlink(rawBaseDir) {
		t.Fatal("base dir should still be a symlink")
	}
	if !isDir(realDir) {
		t.Fatal("real base dir should exist")
	}
	if err := mnt.RemoveAllMetadata(); err != nil {
		t.Fatal(err)
	}
	if !isSymlink(rawBaseDir) {
		t.Fatal("base dir should still be a symlink")
	}
	if isDir(realDir) {
		t.Fatal("real base dir should no longer exist")
	}
}

func TestSetupWithAbsoluteSymlink(t *testing.T) {
	mnt, err := getTestMount(t)
	if err != nil {
		t.Fatal(err)
	}
	tempDir, err := ioutil.TempDir("", "fscrypt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	realDir := filepath.Join(tempDir, "realDir")
	if realDir, err = filepath.Abs(realDir); err != nil {
		t.Fatal(err)
	}
	testSetupWithSymlink(t, mnt, realDir, realDir)
}

func TestSetupWithRelativeSymlink(t *testing.T) {
	mnt, err := getTestMount(t)
	if err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(mnt.Path, ".fscrypt-real")
	testSetupWithSymlink(t, mnt, ".fscrypt-real", realDir)
}

func testSetupMode(t *testing.T, mnt *Mount, setupMode SetupMode, expectedPerms os.FileMode) {
	mnt.RemoveAllMetadata()
	if err := mnt.Setup(setupMode); err != nil {
		t.Fatal(err)
	}
	dirNames := []string{"policies", "protectors"}
	for _, dirName := range dirNames {
		fi, err := os.Stat(filepath.Join(mnt.Path, ".fscrypt", dirName))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&(os.ModeSticky|0777) != expectedPerms {
			t.Errorf("directory %s doesn't have permissions %o", dirName, expectedPerms)
		}
	}
}

// Tests that the supported setup modes (WorldWritable and SingleUserWritable)
// work as intended.
func TestSetupModes(t *testing.T) {
	mnt, err := getTestMount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer mnt.RemoveAllMetadata()
	testSetupMode(t, mnt, WorldWritable, os.ModeSticky|0777)
	testSetupMode(t, mnt, SingleUserWritable, 0755)
}

// Tests that fscrypt refuses to use metadata directories that are
// world-writable but don't have the sticky bit set.
func TestInsecurePermissions(t *testing.T) {
	mnt, err := getTestMount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer mnt.RemoveAllMetadata()

	if err = mnt.Setup(WorldWritable); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(mnt.PolicyDir(), 0777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(mnt.PolicyDir(), os.ModeSticky|0777)
	err = mnt.CheckSetup(nil)
	if _, ok := err.(*ErrInsecurePermissions); !ok {
		t.Fatal("expected ErrInsecurePermissions")
	}
}

// Adding a good Protector should succeed, adding a bad one should fail
func TestAddProtector(t *testing.T) {
	mnt, err := getSetupMount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer mnt.RemoveAllMetadata()

	protector := getFakeProtector()
	if err = mnt.AddProtector(protector, nil); err != nil {
		t.Error(err)
	}

	// Change the source to bad one, or one that requires hashing costs
	protector.Source = metadata.SourceType_default
	if mnt.AddProtector(protector, nil) == nil {
		t.Error("bad source for a descriptor should make metadata invalid")
	}
	protector.Source = metadata.SourceType_custom_passphrase
	if mnt.AddProtector(protector, nil) == nil {
		t.Error("protectors using passphrases should require hashing costs")
	}
	protector.Source = metadata.SourceType_raw_key

	// Use a bad wrapped key
	protector.WrappedKey = wrappedPolicyKey
	if mnt.AddProtector(protector, nil) == nil {
		t.Error("bad length for protector keys should make metadata invalid")
	}
	protector.WrappedKey = wrappedProtectorKey

	// Change the descriptor (to a bad length)
	protector.ProtectorDescriptor = "abcde"
	if mnt.AddProtector(protector, nil) == nil {
		t.Error("bad descriptor length should make metadata invalid")
	}

}

// Adding a good Policy should succeed, adding a bad one should fail
func TestAddPolicy(t *testing.T) {
	mnt, err := getSetupMount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer mnt.RemoveAllMetadata()

	policy := getFakePolicy()
	if err = mnt.AddPolicy(policy, nil); err != nil {
		t.Error(err)
	}

	// Bad encryption options should make policy invalid
	policy.Options.Padding = 7
	if mnt.AddPolicy(policy, nil) == nil {
		t.Error("padding not a power of 2 should make metadata invalid")
	}
	policy.Options.Padding = 16
	policy.Options.Filenames = metadata.EncryptionOptions_default
	if mnt.AddPolicy(policy, nil) == nil {
		t.Error("encryption mode not set should make metadata invalid")
	}
	policy.Options.Filenames = metadata.EncryptionOptions_AES_256_CTS

	// Use a bad wrapped key
	policy.WrappedPolicyKeys[0].WrappedKey = wrappedProtectorKey
	if mnt.AddPolicy(policy, nil) == nil {
		t.Error("bad length for policy keys should make metadata invalid")
	}
	policy.WrappedPolicyKeys[0].WrappedKey = wrappedPolicyKey

	// Change the descriptor (to a bad length)
	policy.KeyDescriptor = "abcde"
	if mnt.AddPolicy(policy, nil) == nil {
		t.Error("bad descriptor length should make metadata invalid")
	}
}

// Tests that we can set a policy and get it back
func TestSetPolicy(t *testing.T) {
	mnt, err := getSetupMount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer mnt.RemoveAllMetadata()

	policy := getFakePolicy()
	if err = mnt.AddPolicy(policy, nil); err != nil {
		t.Fatal(err)
	}

	realPolicy, err := mnt.GetPolicy(policy.KeyDescriptor, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !proto.Equal(realPolicy, policy) {
		t.Errorf("policy %+v does not equal expected policy %+v", realPolicy, policy)
	}

}

// Tests that we can set a normal protector and get it back
func TestSetProtector(t *testing.T) {
	mnt, err := getSetupMount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer mnt.RemoveAllMetadata()

	protector := getFakeProtector()
	if err = mnt.AddProtector(protector, nil); err != nil {
		t.Fatal(err)
	}

	realProtector, err := mnt.GetRegularProtector(protector.ProtectorDescriptor, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !proto.Equal(realProtector, protector) {
		t.Errorf("protector %+v does not equal expected protector %+v", realProtector, protector)
	}
}

// Tests that a login protector whose embedded UID doesn't match the file owner
// is considered invalid.  (Such a file could be created by a malicious user to
// try to confuse fscrypt into processing the wrong file.)
func TestSpoofedLoginProtector(t *testing.T) {
	myUID := int64(os.Geteuid())
	badUID := myUID + 1 // anything different from myUID
	mnt, err := getSetupMount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer mnt.RemoveAllMetadata()

	// Control case: protector with matching UID should be accepted.
	protector := getFakeLoginProtector(myUID)
	if err = mnt.AddProtector(protector, nil); err != nil {
		t.Fatal(err)
	}
	_, err = mnt.GetRegularProtector(protector.ProtectorDescriptor, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = mnt.RemoveProtector(protector.ProtectorDescriptor); err != nil {
		t.Fatal(err)
	}

	// The real test: protector with mismatching UID should rejected,
	// *unless* the process running the tests (and hence the file owner) is
	// root in which case it should be accepted.
	protector = getFakeLoginProtector(badUID)
	if err = mnt.AddProtector(protector, nil); err != nil {
		t.Fatal(err)
	}
	_, err = mnt.GetRegularProtector(protector.ProtectorDescriptor, nil)
	if myUID == 0 {
		if err != nil {
			t.Fatal(err)
		}
	} else {
		if err == nil {
			t.Fatal("reading protector with bad UID unexpectedly succeeded")
		}
	}
}

// Gets a setup mount and a fake second mount
func getTwoSetupMounts(t *testing.T) (realMnt, fakeMnt *Mount, err error) {
	if realMnt, err = getSetupMount(t); err != nil {
		return
	}

	// Create and setup a fake filesystem
	fakeMountpoint := filepath.Join(realMnt.Path, "fake")
	if err = os.MkdirAll(fakeMountpoint, basePermissions); err != nil {
		return
	}
	fakeMnt = &Mount{Path: fakeMountpoint, FilesystemType: realMnt.FilesystemType}
	err = fakeMnt.Setup(WorldWritable)
	return
}

// Removes all the data from the fake and real filesystems
func cleanupTwoMounts(realMnt, fakeMnt *Mount) {
	realMnt.RemoveAllMetadata()
	os.RemoveAll(fakeMnt.Path)
}

// Tests that we can set a linked protector and get it back
func TestLinkedProtector(t *testing.T) {
	realMnt, fakeMnt, err := getTwoSetupMounts(t)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupTwoMounts(realMnt, fakeMnt)

	// Add the protector to the first filesystem
	protector := getFakeProtector()
	if err = realMnt.AddProtector(protector, nil); err != nil {
		t.Fatal(err)
	}

	// Add the link to the second filesystem
	var isNewLink bool
	if isNewLink, err = fakeMnt.AddLinkedProtector(protector.ProtectorDescriptor, realMnt, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !isNewLink {
		t.Fatal("Link was not new")
	}
	if isNewLink, err = fakeMnt.AddLinkedProtector(protector.ProtectorDescriptor, realMnt, nil, nil); err != nil {
		t.Fatal(err)
	}
	if isNewLink {
		t.Fatal("Link was new")
	}

	// Get the protector though the second system
	_, err = fakeMnt.GetRegularProtector(protector.ProtectorDescriptor, nil)
	if _, ok := err.(*ErrProtectorNotFound); !ok {
		t.Fatal(err)
	}

	retMnt, retProtector, err := fakeMnt.GetProtector(protector.ProtectorDescriptor, nil)
	if err != nil {
		t.Fatal(err)
	}
	if retMnt != realMnt {
		t.Error("mount returned was incorrect")
	}

	if !proto.Equal(retProtector, protector) {
		t.Errorf("protector %+v does not equal expected protector %+v", retProtector, protector)
	}
}

func createFile(path string, size int64) error {
	if err := ioutil.WriteFile(path, []byte{}, 0600); err != nil {
		return err
	}
	return os.Truncate(path, size)
}

// Tests the readMetadataFileSafe() function.
func TestReadMetadataFileSafe(t *testing.T) {
	currentUser, err := util.EffectiveUser()
	otherUser := &user.User{Uid: "-1"}
	if err != nil {
		t.Fatal(err)
	}
	tempDir, err := ioutil.TempDir("", "fscrypt")
	if err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(tempDir, "file")
	defer os.RemoveAll(tempDir)

	// Good file (control case)
	if err = createFile(filePath, 1000); err != nil {
		t.Fatal(err)
	}
	_, owner, err := readMetadataFileSafe(filePath, nil)
	if err != nil {
		t.Fatal("failed to read file")
	}
	if owner != int64(os.Geteuid()) {
		t.Fatal("got wrong owner")
	}
	// Also try it with the trustedUser argument set to the current user.
	if _, _, err = readMetadataFileSafe(filePath, currentUser); err != nil {
		t.Fatal("failed to read file")
	}
	os.Remove(filePath)

	// File owned by another user.  We might not have permission to actually
	// change the file's ownership, so we simulate this by passing in a bad
	// value for the trustedUser argument.
	if err = createFile(filePath, 1000); err != nil {
		t.Fatal(err)
	}
	_, _, err = readMetadataFileSafe(filePath, otherUser)
	if util.IsUserRoot() {
		if err != nil {
			t.Fatal("root-owned file didn't pass owner validation")
		}
	} else {
		if err == nil {
			t.Fatal("unexpectedly could read file owned by another user")
		}
	}
	os.Remove(filePath)

	// Nonexistent file
	_, _, err = readMetadataFileSafe(filePath, nil)
	if !os.IsNotExist(err) {
		t.Fatal("trying to read nonexistent file didn't fail with expected error")
	}

	// Symlink
	if err = os.Symlink("target", filePath); err != nil {
		t.Fatal(err)
	}
	_, _, err = readMetadataFileSafe(filePath, nil)
	if err.(*os.PathError).Err != syscall.ELOOP {
		t.Fatal("trying to read symlink didn't fail with ELOOP")
	}
	os.Remove(filePath)

	// FIFO
	if err = unix.Mkfifo(filePath, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err = readMetadataFileSafe(filePath, nil)
	if _, ok := err.(*ErrCorruptMetadata); !ok {
		t.Fatal("trying to read FIFO didn't fail with expected error")
	}
	os.Remove(filePath)

	// Very large file
	if err = createFile(filePath, 1000000); err != nil {
		t.Fatal(err)
	}
	_, _, err = readMetadataFileSafe(filePath, nil)
	if _, ok := err.(*ErrCorruptMetadata); !ok {
		t.Fatal("trying to read very large file didn't fail with expected error")
	}
}

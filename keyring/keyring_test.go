/*
 * keyring_test.go - tests for the keyring package
 *
 * Copyright 2017 Google Inc.
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

package keyring

import (
	"os/user"
	"strconv"
	"testing"

	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/util"
)

// Reader that always returns the same byte
type ConstReader byte

func (r ConstReader) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = byte(r)
	}
	return len(b), nil
}

// Makes a key of the same repeating byte
func makeKey(b byte, n int) (*crypto.Key, error) {
	return crypto.NewFixedLengthKeyFromReader(ConstReader(b), n)
}

var (
	testUser, _             = util.EffectiveUser()
	fakeValidPolicyKey, _   = makeKey(42, metadata.PolicyKeyLen)
	fakeInvalidPolicyKey, _ = makeKey(42, metadata.PolicyKeyLen-1)
	fakeV1Descriptor        = "0123456789abcdef"
	fakeV2Descriptor, _     = crypto.ComputeKeyDescriptor(fakeValidPolicyKey, 2)
)

func assertKeyStatus(t *testing.T, descriptor string, options *Options,
	expectedStatus KeyStatus) {
	status, err := GetEncryptionKeyStatus(descriptor, options)
	if err != nil {
		t.Error(err)
	}
	if status != expectedStatus {
		t.Errorf("Expected key status %v but got key status %v", expectedStatus, status)
	}
}

// getTestMount retrieves the Mount for a test filesystem, or skips the test if
// no test filesystem is available.
func getTestMount(t *testing.T) *filesystem.Mount {
	root, err := util.TestRoot()
	if err != nil {
		t.Skip(err)
	}
	mount, err := filesystem.GetMount(root)
	if err != nil {
		t.Skip(err)
	}
	return mount
}

// getTestMountV2 is like getTestMount, but it also checks that the
// filesystem keyring and v2 encryption policies are supported.
func getTestMountV2(t *testing.T) *filesystem.Mount {
	mount := getTestMount(t)
	if !IsFsKeyringSupported(mount) {
		t.Skip("No support for fs keyring, skipping test.")
	}
	return mount
}

func requireRoot(t *testing.T) {
	if !util.IsUserRoot() {
		t.Skip("Not root, skipping test.")
	}
}

// getNonRootUsers checks for root permission, then returns the users for uids
// 1000...1000+count-1.  If this fails, the test is skipped.
func getNonRootUsers(t *testing.T, count int) []*user.User {
	requireRoot(t)
	users := make([]*user.User, count)
	for i := 0; i < count; i++ {
		uid := 1000 + i
		user, err := user.LookupId(strconv.Itoa(uid))
		if err != nil {
			t.Skip(err)
		}
		users[i] = user
	}
	return users
}

func getOptionsForFsKeyringUsers(t *testing.T, numNonRootUsers int) (rootOptions *Options, userOptions []*Options) {
	mount := getTestMountV2(t)
	nonRootUsers := getNonRootUsers(t, numNonRootUsers)
	rootOptions = &Options{
		Mount: mount,
		User:  testUser,
	}
	userOptions = make([]*Options, numNonRootUsers)
	for i := 0; i < numNonRootUsers; i++ {
		userOptions[i] = &Options{
			Mount: mount,
			User:  nonRootUsers[i],
		}
	}
	return
}

// testAddAndRemoveKey does the common tests for adding+removing keys that are
// run in multiple configurations (v1 policies with user keyring, v1 policies
// with fs keyring, and v2 policies with fs keyring).
func testAddAndRemoveKey(t *testing.T, descriptor string, options *Options) {

	// Basic add, get status, and remove
	if err := AddEncryptionKey(fakeValidPolicyKey, descriptor, options); err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, descriptor, options, KeyPresent)
	if err := RemoveEncryptionKey(descriptor, options, false); err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, descriptor, options, KeyAbsent)
	err := RemoveEncryptionKey(descriptor, options, false)
	if err != ErrKeyNotPresent {
		t.Error(err)
	}

	// Adding a key twice should succeed
	if err := AddEncryptionKey(fakeValidPolicyKey, descriptor, options); err != nil {
		t.Error(err)
	}
	if err := AddEncryptionKey(fakeValidPolicyKey, descriptor, options); err != nil {
		t.Error("AddEncryptionKey should not fail if key already exists")
	}
	RemoveEncryptionKey(descriptor, options, false)
	assertKeyStatus(t, descriptor, options, KeyAbsent)

	// Adding a key with wrong length should fail
	if err := AddEncryptionKey(fakeInvalidPolicyKey, descriptor, options); err == nil {
		RemoveEncryptionKey(descriptor, options, false)
		t.Error("AddEncryptionKey should fail with wrong-length key")
	}
	assertKeyStatus(t, descriptor, options, KeyAbsent)
}

func TestUserKeyring(t *testing.T) {
	mount := getTestMount(t)
	options := &Options{
		Mount:                     mount,
		User:                      testUser,
		UseFsKeyringForV1Policies: false,
	}
	testAddAndRemoveKey(t, fakeV1Descriptor, options)
}

func TestFsKeyringV1PolicyKey(t *testing.T) {
	requireRoot(t)
	mount := getTestMountV2(t)
	options := &Options{
		Mount:                     mount,
		User:                      testUser,
		UseFsKeyringForV1Policies: true,
	}
	testAddAndRemoveKey(t, fakeV1Descriptor, options)
}

func TestV2PolicyKey(t *testing.T) {
	mount := getTestMountV2(t)
	options := &Options{
		Mount: mount,
		User:  testUser,
	}
	testAddAndRemoveKey(t, fakeV2Descriptor, options)
}

func TestV2PolicyKeyCannotBeRemovedByAnotherUser(t *testing.T) {
	rootOptions, userOptions := getOptionsForFsKeyringUsers(t, 2)
	user1Options := userOptions[0]
	user2Options := userOptions[1]

	// Add key as non-root user.
	if err := AddEncryptionKey(fakeValidPolicyKey, fakeV2Descriptor, user1Options); err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, fakeV2Descriptor, user1Options, KeyPresent)
	assertKeyStatus(t, fakeV2Descriptor, user2Options, KeyPresentButOnlyOtherUsers)
	assertKeyStatus(t, fakeV2Descriptor, rootOptions, KeyPresentButOnlyOtherUsers)

	// Key shouldn't be removable by another user, even root.
	err := RemoveEncryptionKey(fakeV2Descriptor, user2Options, false)
	if err != ErrKeyAddedByOtherUsers {
		t.Error(err)
	}
	assertKeyStatus(t, fakeV2Descriptor, user1Options, KeyPresent)
	assertKeyStatus(t, fakeV2Descriptor, user2Options, KeyPresentButOnlyOtherUsers)
	assertKeyStatus(t, fakeV2Descriptor, rootOptions, KeyPresentButOnlyOtherUsers)
	err = RemoveEncryptionKey(fakeV2Descriptor, rootOptions, false)
	if err != ErrKeyAddedByOtherUsers {
		t.Error(err)
	}
	assertKeyStatus(t, fakeV2Descriptor, user1Options, KeyPresent)
	assertKeyStatus(t, fakeV2Descriptor, user2Options, KeyPresentButOnlyOtherUsers)
	assertKeyStatus(t, fakeV2Descriptor, rootOptions, KeyPresentButOnlyOtherUsers)

	if err := RemoveEncryptionKey(fakeV2Descriptor, user1Options, false); err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, fakeV2Descriptor, user1Options, KeyAbsent)
	assertKeyStatus(t, fakeV2Descriptor, user2Options, KeyAbsent)
	assertKeyStatus(t, fakeV2Descriptor, rootOptions, KeyAbsent)
}

func TestV2PolicyKeyMultipleUsers(t *testing.T) {
	rootOptions, userOptions := getOptionsForFsKeyringUsers(t, 2)
	user1Options := userOptions[0]
	user2Options := userOptions[1]

	// Add key as two non-root users.
	if err := AddEncryptionKey(fakeValidPolicyKey, fakeV2Descriptor, user1Options); err != nil {
		t.Error(err)
	}
	if err := AddEncryptionKey(fakeValidPolicyKey, fakeV2Descriptor, user2Options); err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, fakeV2Descriptor, user1Options, KeyPresent)
	assertKeyStatus(t, fakeV2Descriptor, user2Options, KeyPresent)
	assertKeyStatus(t, fakeV2Descriptor, rootOptions, KeyPresentButOnlyOtherUsers)

	// Remove key as one user.
	err := RemoveEncryptionKey(fakeV2Descriptor, user1Options, false)
	if err != ErrKeyAddedByOtherUsers {
		t.Error(err)
	}
	assertKeyStatus(t, fakeV2Descriptor, user1Options, KeyPresentButOnlyOtherUsers)
	assertKeyStatus(t, fakeV2Descriptor, user2Options, KeyPresent)
	assertKeyStatus(t, fakeV2Descriptor, rootOptions, KeyPresentButOnlyOtherUsers)

	// Remove key as the other user.
	err = RemoveEncryptionKey(fakeV2Descriptor, user2Options, false)
	if err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, fakeV2Descriptor, user1Options, KeyAbsent)
	assertKeyStatus(t, fakeV2Descriptor, user2Options, KeyAbsent)
	assertKeyStatus(t, fakeV2Descriptor, rootOptions, KeyAbsent)
}

func TestV2PolicyKeyWrongDescriptor(t *testing.T) {
	mount := getTestMountV2(t)
	options := &Options{
		Mount: mount,
		User:  testUser,
	}
	// one wrong but valid hex, and one not valid hex
	wrongV2Descriptors := []string{"abcdabcdabcdabcdabcdabcdabcdabcd", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"}

	for _, desc := range wrongV2Descriptors {
		if err := AddEncryptionKey(fakeValidPolicyKey, desc, options); err == nil {
			RemoveEncryptionKey(desc, options, false)
			t.Error("For v2 policy keys, AddEncryptionKey should fail if the descriptor is wrong")
		}
	}
}

func TestV2PolicyKeyBadMount(t *testing.T) {
	options := &Options{
		Mount: &filesystem.Mount{Path: "/NONEXISTENT_MOUNT"},
		User:  testUser,
	}
	if err := AddEncryptionKey(fakeValidPolicyKey, fakeV2Descriptor, options); err == nil {
		RemoveEncryptionKey(fakeV2Descriptor, options, false)
		t.Error("AddEncryptionKey should have failed with bad mount!")
	}
	if err := RemoveEncryptionKey(fakeV2Descriptor, options, false); err == nil {
		t.Error("RemoveEncryptionKey should have failed with bad mount!")
	}
	status, err := GetEncryptionKeyStatus(fakeV2Descriptor, options)
	if err == nil {
		t.Error("GetEncryptionKeyStatus should have failed with bad mount!")
	}
	if status != KeyStatusUnknown {
		t.Error("GetEncryptionKeyStatus should have returned unknown status!")
	}
}

func TestV2PolicyKeyRemoveForAllUsers(t *testing.T) {
	rootOptions, userOptions := getOptionsForFsKeyringUsers(t, 2)
	user1Options := userOptions[0]
	user2Options := userOptions[1]

	// Add key as two non-root users.
	if err := AddEncryptionKey(fakeValidPolicyKey, fakeV2Descriptor, user1Options); err != nil {
		t.Error(err)
	}
	if err := AddEncryptionKey(fakeValidPolicyKey, fakeV2Descriptor, user2Options); err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, fakeV2Descriptor, user1Options, KeyPresent)
	assertKeyStatus(t, fakeV2Descriptor, user2Options, KeyPresent)
	assertKeyStatus(t, fakeV2Descriptor, rootOptions, KeyPresentButOnlyOtherUsers)

	// Remove key for all users as root.
	err := RemoveEncryptionKey(fakeV2Descriptor, rootOptions, true)
	if err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, fakeV2Descriptor, user1Options, KeyAbsent)
	assertKeyStatus(t, fakeV2Descriptor, user2Options, KeyAbsent)
	assertKeyStatus(t, fakeV2Descriptor, rootOptions, KeyAbsent)
}

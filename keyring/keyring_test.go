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
	"testing"

	"golang.org/x/sys/unix"

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
	defaultService          = unix.FSCRYPT_KEY_DESC_PREFIX
	testUser, _             = util.EffectiveUser()
	fakeValidPolicyKey, _   = makeKey(42, metadata.PolicyKeyLen)
	fakeInvalidPolicyKey, _ = makeKey(42, metadata.PolicyKeyLen-1)
	fakeV1Descriptor        = "0123456789abcdef"
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

// getTestMountV2 is like getTestMount, but it also checks that the filesystem
// keyring is supported.
func getTestMountV2(t *testing.T) *filesystem.Mount {
	mount := getTestMount(t)
	if !isFsKeyringSupported(mount) {
		t.Skip("No support for fs keyring, skipping test.")
	}
	return mount
}

func requireRoot(t *testing.T) {
	if !util.IsUserRoot() {
		t.Skip("Not root, skipping test.")
	}
}

// testAddAndRemoveKey does the common tests for adding+removing keys that are
// run in multiple configurations (v1 policies with user keyring and v1 policies
// with fs keyring).
func testAddAndRemoveKey(t *testing.T, descriptor string, options *Options) {

	// Basic add, get status, and remove
	if err := AddEncryptionKey(fakeValidPolicyKey, descriptor, options); err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, descriptor, options, KeyPresent)
	if err := RemoveEncryptionKey(descriptor, options); err != nil {
		t.Error(err)
	}
	assertKeyStatus(t, descriptor, options, KeyAbsent)
	err := RemoveEncryptionKey(descriptor, options)
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
	RemoveEncryptionKey(descriptor, options)
	assertKeyStatus(t, descriptor, options, KeyAbsent)

	// Adding a key with wrong length should fail
	if err := AddEncryptionKey(fakeInvalidPolicyKey, descriptor, options); err == nil {
		RemoveEncryptionKey(descriptor, options)
		t.Error("AddEncryptionKey should fail with wrong-length key")
	}
	assertKeyStatus(t, descriptor, options, KeyAbsent)
}

func TestUserKeyringDefaultService(t *testing.T) {
	options := &Options{
		User:                      testUser,
		Service:                   defaultService,
		UseFsKeyringForV1Policies: false,
	}
	testAddAndRemoveKey(t, fakeV1Descriptor, options)
}

func TestUserKeyringExt4Service(t *testing.T) {
	options := &Options{
		User:                      testUser,
		Service:                   "ext4:",
		UseFsKeyringForV1Policies: false,
	}
	testAddAndRemoveKey(t, fakeV1Descriptor, options)
}

func TestUserKeyringF2fsService(t *testing.T) {
	options := &Options{
		User:                      testUser,
		Service:                   "f2fs:",
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

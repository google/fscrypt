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
	fakeValidDescriptor     = "0123456789abcdef"
	defaultService          = unix.FSCRYPT_KEY_DESC_PREFIX
	testUser, _             = util.EffectiveUser()
	fakeValidPolicyKey, _   = makeKey(42, metadata.PolicyKeyLen)
	fakeInvalidPolicyKey, _ = makeKey(42, metadata.PolicyKeyLen-1)
)

// Adds and removes a key with various services.
func TestAddRemoveKeys(t *testing.T) {
	for _, service := range []string{defaultService, "ext4:", "f2fs:"} {
		options := &Options{
			User:    testUser,
			Service: service,
		}
		if err := AddEncryptionKey(fakeValidPolicyKey, fakeValidDescriptor, options); err != nil {
			t.Error(err)
		}
		if err := RemoveEncryptionKey(fakeValidDescriptor, options); err != nil {
			t.Error(err)
		}
	}
}

// Adds a key twice (both should succeed)
func TestAddTwice(t *testing.T) {
	options := &Options{
		User:    testUser,
		Service: defaultService,
	}
	if err := AddEncryptionKey(fakeValidPolicyKey, fakeValidDescriptor, options); err != nil {
		t.Error(err)
	}
	if err := AddEncryptionKey(fakeValidPolicyKey, fakeValidDescriptor, options); err != nil {
		t.Error("AddEncryptionKey should not fail if key already exists")
	}
	RemoveEncryptionKey(fakeValidDescriptor, options)
}

// Makes sure trying to add a key of the wrong length fails
func TestAddWrongLengthKey(t *testing.T) {
	options := &Options{
		User:    testUser,
		Service: defaultService,
	}
	if err := AddEncryptionKey(fakeInvalidPolicyKey, fakeValidDescriptor, options); err == nil {
		RemoveEncryptionKey(fakeValidDescriptor, options)
		t.Error("AddEncryptionKey should fail with wrong-length key")
	}
}

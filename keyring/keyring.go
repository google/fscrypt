/*
 * keyring.go - Add/remove encryption policy keys to/from kernel
 *
 * Copyright 2019 Google LLC
 * Author: Eric Biggers (ebiggers@google.com)
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

// Package keyring manages adding, removing, and getting the status of
// encryption policy keys to/from the kernel.  Most public functions are in
// keyring.go, and they delegate to user_keyring.go.
package keyring

import (
	"os/user"
	"strconv"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/util"
)

// Keyring error values
var (
	ErrKeyAdd            = util.SystemError("could not add key to the keyring")
	ErrKeyRemove         = util.SystemError("could not remove key from the keyring")
	ErrKeyNotPresent     = errors.New("key not present or already removed")
	ErrKeySearch         = errors.New("could not find key with descriptor")
	ErrSessionUserKeying = errors.New("user keyring not linked into session keyring")
	ErrAccessUserKeyring = errors.New("could not access user keyring")
	ErrLinkUserKeyring   = util.SystemError("could not link user keyring into root keyring")
)

// Options are the options which specify *which* keyring the key should be
// added/removed/gotten to, and how.
type Options struct {
	// User is the user for whom the key should be added/removed/gotten.
	User *user.User
	// Service is the prefix to prepend to the description of the keys.
	Service string
}

// AddEncryptionKey adds an encryption policy key to a kernel keyring.
func AddEncryptionKey(key *crypto.Key, descriptor string, options *Options) error {
	if err := util.CheckValidLength(metadata.PolicyKeyLen, key.Len()); err != nil {
		return errors.Wrap(err, "policy key")
	}
	return userAddKey(key, options.Service+descriptor, options.User)
}

// RemoveEncryptionKey removes an encryption policy key from a kernel keyring.
func RemoveEncryptionKey(descriptor string, options *Options) error {
	return userRemoveKey(options.Service+descriptor, options.User)
}

// KeyStatus is an enum that represents the status of a key in a kernel keyring.
type KeyStatus int

// The possible values of KeyStatus.
const (
	KeyStatusUnknown = 0 + iota
	KeyAbsent
	KeyPresent
)

func (status KeyStatus) String() string {
	switch status {
	case KeyStatusUnknown:
		return "Unknown"
	case KeyAbsent:
		return "Absent"
	case KeyPresent:
		return "Present"
	default:
		return strconv.Itoa(int(status))
	}
}

// GetEncryptionKeyStatus gets the status of an encryption policy key in a
// kernel keyring.
func GetEncryptionKeyStatus(descriptor string, options *Options) (KeyStatus, error) {
	_, err := userFindKey(options.Service+descriptor, options.User)
	if err != nil {
		return KeyAbsent, nil
	}
	return KeyPresent, nil
}

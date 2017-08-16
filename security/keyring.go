/*
 * privileges.go - Handles inserting/removing into user keyrings.
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

package security

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	// file which lists all visible keys
	keyListFilename = "/proc/keys"
	// keyType is always logon as required by filesystem encryption.
	keyType = "logon"
)

// FindKey tries to locate a key in the kernel keyring with the provided
// description. The key id is returned if we can find the key. An error is
// returned if the key does not exist.
func FindKey(description string) (int, error) {
	keyringID, err := getUserKeyringID()
	if err != nil {
		return 0, err
	}

	keyID, err := unix.KeyctlSearch(keyringID, keyType, description, 0)
	log.Printf("KeyctlSearch(%d, %s, %s) = %d, %v", keyringID, keyType, description, keyID, err)
	if err != nil {
		return 0, errors.Wrap(ErrKeyringSearch, err.Error())
	}
	return keyID, err
}

// RemoveKey tries to remove a policy key from the kernel keyring with the
// provided description. An error is returned if the key does not exist.
func RemoveKey(description string) error {
	keyID, err := FindKey(description)
	if err != nil {
		return err
	}

	// We use KEYCTL_INVALIDATE instead of KEYCTL_REVOKE because
	// invalidating a key immediately removes it.
	_, err = unix.KeyctlInt(unix.KEYCTL_INVALIDATE, keyID, 0, 0, 0)
	log.Printf("KeyctlInvalidate(%d) = %v", keyID, err)
	if err != nil {
		return errors.Wrap(ErrKeyringDelete, err.Error())
	}
	return nil
}

// InsertKey puts the provided data into the kernel keyring with the provided
// description.
func InsertKey(data []byte, description string) error {
	keyringID, err := getUserKeyringID()
	if err != nil {
		return err
	}

	keyID, err := unix.AddKey(keyType, description, data, keyringID)
	log.Printf("KeyctlAddKey(%s, %s, <data>, %d) = %d, %v",
		keyType, description, keyringID, keyID, err)
	if err != nil {
		return errors.Wrap(ErrKeyringInsert, err.Error())
	}
	return nil
}

var keyringIDCache = make(map[int]int)

// getUserKeyringID returns the key id of the current user's user keyring. A
// simpler approach would be to use
//     unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, false)
// which would work in almost all cases. However, despite the fact that the rest
// of the keyrings API using the _effective_ UID throughout, the translation of
// KEY_SPEC_USER_KEYRING is done with respect to the _real_ UID. This means that
// a simpler implementation would not respect permissions dropping.
func getUserKeyringID() (int, error) {
	// We will cache the result of this function.
	euid := unix.Geteuid()
	if keyringID, ok := keyringIDCache[euid]; ok {
		return keyringID, nil
	}

	data, err := ioutil.ReadFile(keyListFilename)
	if err != nil {
		log.Print(err)
		return 0, ErrReadingKeyList
	}

	expectedName := fmt.Sprintf("_uid.%d:", euid)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}

		// Each line in /proc/keys should have 9 columns.
		columns := bytes.Fields(line)
		if len(columns) < 9 {
			return 0, ErrReadingKeyList
		}
		hexID := string(columns[0])
		owner := string(columns[5])
		name := string(columns[8])

		// Our desired key is owned by the user and has the right name.
		// The owner check is so another user cannot DOS this user by
		// inserting a keyring with a similar name.
		if owner != strconv.Itoa(euid) || name != expectedName {
			continue
		}

		// The keyring's ID is encoded as hex.
		parsedID, err := strconv.ParseInt(hexID, 16, 32)
		if err != nil {
			log.Print(err)
			return 0, ErrReadingKeyList
		}

		keyringID := int(parsedID)
		keyringIDCache[euid] = keyringID
		return keyringID, nil
	}

	return 0, ErrFindingKeyring
}

func keyringLink(keyID int, keyringID int) error {
	_, err := unix.KeyctlInt(unix.KEYCTL_LINK, keyID, keyringID, 0, 0)
	return errors.Wrapf(err, "linking key %d into keyring %d", keyID, keyringID)
}

func keyringUnlink(keyID int, keyringID int) error {
	_, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, keyringID, 0, 0)
	return errors.Wrapf(err, "unlinking key %d from keyring %d", keyID, keyringID)
}

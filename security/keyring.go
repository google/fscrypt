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
	"fmt"
	"log"
	"os/user"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/util"
)

// KeyType is always logon as required by filesystem encryption.
const KeyType = "logon"

// Keyring related error values
var (
	ErrKeySearch         = errors.New("could not find key with descriptor")
	ErrKeyRemove         = util.SystemError("could not remove key from the keyring")
	ErrKeyInsert         = util.SystemError("could not insert key into the keyring")
	ErrSessionUserKeying = errors.New("user keyring not linked into session keyring")
	ErrAccessUserKeyring = errors.New("could not access user keyring")
	ErrLinkUserKeyring   = util.SystemError("could not link user keyring into root keyring")
)

// FindKey tries to locate a key in the kernel keyring with the provided
// description. The key ID is returned if we can find the key. An error is
// returned if the key does not exist.
func FindKey(description string, target *user.User) (int, error) {
	keyringID, err := UserKeyringID(target, false)
	if err != nil {
		return 0, err
	}

	keyID, err := unix.KeyctlSearch(keyringID, KeyType, description, 0)
	log.Printf("KeyctlSearch(%d, %s, %s) = %d, %v", keyringID, KeyType, description, keyID, err)
	if err != nil {
		return 0, errors.Wrap(ErrKeySearch, err.Error())
	}
	return keyID, err
}

// RemoveKey tries to remove a policy key from the kernel keyring with the
// provided description. An error is returned if the key does not exist.
func RemoveKey(description string, target *user.User) error {
	keyID, err := FindKey(description, target)
	if err != nil {
		return err
	}

	// We use KEYCTL_INVALIDATE instead of KEYCTL_REVOKE because
	// invalidating a key immediately removes it.
	_, err = unix.KeyctlInt(unix.KEYCTL_INVALIDATE, keyID, 0, 0, 0)
	log.Printf("KeyctlInvalidate(%d) = %v", keyID, err)
	if err != nil {
		return errors.Wrap(ErrKeyRemove, err.Error())
	}
	return nil
}

// InsertKey puts the provided data into the kernel keyring with the provided
// description.
func InsertKey(data []byte, description string, target *user.User) error {
	keyringID, err := UserKeyringID(target, true)
	if err != nil {
		return err
	}

	keyID, err := unix.AddKey(KeyType, description, data, keyringID)
	log.Printf("KeyctlAddKey(%s, %s, <data>, %d) = %d, %v",
		KeyType, description, keyringID, keyID, err)
	if err != nil {
		return errors.Wrap(ErrKeyInsert, err.Error())
	}
	return nil
}

var (
	keyringIDCache = make(map[int]int)
	cacheLock      sync.Mutex
)

// UserKeyringID returns the key id of the target user's user keyring. We also
// ensure that the keyring will be accessible by linking it into the process
// keyring and linking it into the root user keyring (permissions allowing). If
// checkSession is true, an error is returned if a normal user requests their
// user keyring, but it is not in the current session keyring.
func UserKeyringID(target *user.User, checkSession bool) (int, error) {
	uid := util.AtoiOrPanic(target.Uid)
	targetKeyring, err := userKeyringIDLookup(uid)
	if err != nil {
		return 0, errors.Wrap(ErrAccessUserKeyring, err.Error())
	}

	if !util.IsUserRoot() {
		// Make sure the returned keyring will be accessible by checking
		// that it is in the session keyring.
		if checkSession && !isUserKeyringInSession(uid) {
			return 0, ErrSessionUserKeying
		}
		return targetKeyring, nil
	}

	// Make sure the returned keyring will be accessible by linking it into
	// the root user's user keyring (which will not be garbage collected).
	rootKeyring, err := userKeyringIDLookup(0)
	if err != nil {
		return 0, errors.Wrap(ErrLinkUserKeyring, err.Error())
	}

	if rootKeyring != targetKeyring {
		if err = keyringLink(targetKeyring, rootKeyring); err != nil {
			return 0, errors.Wrap(ErrLinkUserKeyring, err.Error())
		}
	}
	return targetKeyring, nil
}

func userKeyringIDLookup(uid int) (keyringID int, err error) {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	var ok bool
	if keyringID, ok = keyringIDCache[uid]; ok {
		return
	}

	// Our goals here are to:
	//    - Find the user keyring (for the provided uid)
	//    - Link it into the current process keyring (so we can use it)
	//    - Make no permenant changes to the process privileges
	// Complicating this are the facts that:
	//    - The value of KEY_SPEC_USER_KEYRING is determined by the ruid
	//    - Keyring linking permissions use the euid
	// So we have to change both the ruid and euid to make this work,
	// setting the suid to 0 so that we can later switch back.
	ruid, euid, suid := getUids()
	if ruid != uid || euid != uid {
		if err = setUids(uid, uid, 0); err != nil {
			return
		}
		defer func() {
			resetErr := setUids(ruid, euid, suid)
			if resetErr != nil {
				err = resetErr
			}
		}()
	}

	// We get the value of KEY_SPEC_USER_KEYRING. Note that this will also
	// trigger the creation of the uid keyring if it does not yet exist.
	keyringID, err = unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, true)
	log.Printf("keyringID(_uid.%d) = %d, %v", uid, keyringID, err)
	if err != nil {
		return 0, err
	}

	// We still want to use this keyring after our privileges are reset. So
	// we link it into the process keyring, preventing a loss of access.
	if err = keyringLink(keyringID, unix.KEY_SPEC_PROCESS_KEYRING); err != nil {
		return 0, err
	}

	keyringIDCache[uid] = keyringID
	return keyringID, nil
}

// isUserKeyringInSession tells us if the user's uid keyring is in the current
// session keyring.
func isUserKeyringInSession(uid int) bool {
	// We cannot use unix.KEY_SPEC_SESSION_KEYRING directly as that might
	// create a session keyring if one does not exist.
	sessionKeyring, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, false)
	log.Printf("keyringID(session) = %d, %v", sessionKeyring, err)
	if err != nil {
		return false
	}

	description := fmt.Sprintf("_uid.%d", uid)
	id, err := unix.KeyctlSearch(sessionKeyring, "keyring", description, 0)
	log.Printf("KeyctlSearch(%d, keyring, %s) = %d, %v", sessionKeyring, description, id, err)
	return err == nil
}

func keyringLink(keyID int, keyringID int) error {
	_, err := unix.KeyctlInt(unix.KEYCTL_LINK, keyID, keyringID, 0, 0)
	log.Printf("KeyctlLink(%d, %d) = %v", keyID, keyringID, err)
	return err
}

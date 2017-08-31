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
	"log"
	"os"
	"os/user"
	"runtime"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/util"
)

// KeyType is always logon as required by filesystem encryption.
const KeyType = "logon"

// Keyring related error values
var (
	ErrFindingKeyring = util.SystemError("could not find user keyring")
	ErrKeyringInsert  = util.SystemError("could not insert key into the keyring")
	ErrKeyringSearch  = errors.New("could not find key with descriptor")
	ErrKeyringDelete  = util.SystemError("could not delete key from the keyring")
	ErrKeyringLink    = util.SystemError("could not link keyring")
)

// KeyringsSetup configures the desired keyring linkage by linking the target
// user's keying into the privileged user's keyring.
func KeyringsSetup(target, privileged *user.User) error {
	targetKeyringID, err := userKeyringID(target)
	if err != nil {
		return err
	}
	privilegedKeyringID, err := userKeyringID(privileged)
	if err != nil {
		return err
	}
	return keyringLink(targetKeyringID, privilegedKeyringID)
}

// FindKey tries to locate a key in the kernel keyring with the provided
// description. The key ID is returned if we can find the key. An error is
// returned if the key does not exist.
func FindKey(description string, target *user.User) (int, error) {
	keyringID, err := userKeyringID(target)
	if err != nil {
		return 0, err
	}

	keyID, err := unix.KeyctlSearch(keyringID, KeyType, description, 0)
	log.Printf("KeyctlSearch(%d, %s, %s) = %d, %v", keyringID, KeyType, description, keyID, err)
	if err != nil {
		return 0, errors.Wrap(ErrKeyringSearch, err.Error())
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
		return errors.Wrap(ErrKeyringDelete, err.Error())
	}
	return nil
}

// InsertKey puts the provided data into the kernel keyring with the provided
// description.
func InsertKey(data []byte, description string, target *user.User) error {
	keyringID, err := userKeyringID(target)
	if err != nil {
		return err
	}

	keyID, err := unix.AddKey(KeyType, description, data, keyringID)
	log.Printf("KeyctlAddKey(%s, %s, <data>, %d) = %d, %v",
		KeyType, description, keyringID, keyID, err)
	if err != nil {
		return errors.Wrap(ErrKeyringInsert, err.Error())
	}
	return nil
}

var (
	keyringIDCache = make(map[int]int)
	cacheLock      sync.Mutex
)

// userKeyringID returns the key id of the target user's keyring. The returned
// keyring will also be linked into the process keyring so that it will be
// accessible thoughout the program.
func userKeyringID(target *user.User) (int, error) {
	uid := util.AtoiOrPanic(target.Uid)
	// We will cache the result of this function.
	cacheLock.Lock()
	defer cacheLock.Unlock()
	if keyringID, ok := keyringIDCache[uid]; ok {
		return keyringID, nil
	}

	// The permissions of the keyrings API is a little strange. The euid is
	// used to determine if we can access/modify a key/keyring. However, the
	// ruid is used to determine KEY_SPEC_USER_KEYRING. This means both the
	// ruid and euid must match the user's uid for the lookup to work.
	if uid == os.Getuid() && uid == os.Geteuid() {
		log.Printf("Normal keyring lookup for uid=%d", uid)
		return userKeyringIDLookup(uid)
	}

	// We drop permissions in a separate thread (guaranteed as the main
	// thread is locked) because we need to drop the real AND effective IDs.
	log.Printf("Threaded keyring lookup for uid=%d", uid)
	idChan := make(chan int)
	errChan := make(chan error)
	// OSThread locks ensure the privilege change is only for the lookup.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	go func() {
		runtime.LockOSThread()
		if err := SetThreadPrivileges(target, true); err != nil {
			errChan <- err
			return
		}
		keyringID, err := userKeyringIDLookup(uid)
		if err != nil {
			errChan <- err
			return
		}
		idChan <- keyringID
	}()

	// We select so the thread will have to complete
	select {
	case err := <-errChan:
		return 0, err
	case keyringID := <-idChan:
		if uid == os.Getuid() && uid == os.Geteuid() {
			log.Print("thread privileges now incorrect")
		}
		return keyringID, nil
	}
}

func userKeyringIDLookup(uid int) (int, error) {
	// This will trigger the creation of the user keyring, if necessary.
	keyringID, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, false)
	log.Printf("keyringID(_uid.%d) = %d, %v", uid, keyringID, err)
	if err != nil {
		return 0, errors.Wrap(ErrFindingKeyring, err.Error())
	}

	// For some silly reason, a thread does not automatically "possess" keys
	// in the user keyring. So we link it into the process keyring so that
	// we will not get "permission denied" when purging or modifying keys.
	if err := keyringLink(keyringID, unix.KEY_SPEC_PROCESS_KEYRING); err != nil {
		return 0, err
	}

	keyringIDCache[uid] = keyringID
	return keyringID, nil
}

func keyringLink(keyID int, keyringID int) error {
	_, err := unix.KeyctlInt(unix.KEYCTL_LINK, keyID, keyringID, 0, 0)
	log.Printf("KeyctlLink(%d, %d) = %v", keyID, keyringID, err)
	if err != nil {
		return errors.Wrap(ErrKeyringLink, err.Error())
	}
	return nil
}

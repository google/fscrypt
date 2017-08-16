/*
 * privileges.go - Handles raising and dropping user privileges.
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

// Package security manages:
//  - Keyring Operations (keyring.go)
//  - Privilege manipulation (privileges.go)
//  - Maintaining the link between the root and user keyrings.
package security

import (
	"log"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/util"
)

// Package security error values
var (
	ErrReadingKeyList = util.SystemError("could not read keys from " + keyListFilename)
	ErrFindingKeyring = util.SystemError("could not find user keyring")
	ErrKeyringInsert  = util.SystemError("could not insert key into the keyring")
	ErrKeyringSearch  = errors.New("could not find key with descriptor")
	ErrKeyringDelete  = util.SystemError("could not delete key from the keyring")
)

// Privileges contains the state needed to restore a user's original privileges.
type Privileges struct {
	euid   int
	egid   int
	groups []int
}

// DropThreadPrivileges temporarily drops the privileges of the current thread
// to have the euid and egid specified. The returned opaque Privileges structure
// should later be passed to RestoreThreadPrivileges.
// Due to golang/go#1435, these privileges are only dropped for a single thread.
// This function also makes sure that the appropriate user keyrings are linked.
// This ensures that the user's keys are visible from commands like sudo.
func DropThreadPrivileges(euid int, egid int) (*Privileges, error) {
	var err error
	privs := &Privileges{
		euid: unix.Geteuid(),
		egid: unix.Getegid(),
	}
	if privs.groups, err = unix.Getgroups(); err != nil {
		return nil, errors.Wrapf(err, "getting groups")
	}

	// We link the privileged keyring into the thread keyring so that we
	// can still modify it after dropping privileges.
	privilegedUserKeyringID, err := getUserKeyringID()
	if err != nil {
		return nil, err
	}
	if err = keyringLink(privilegedUserKeyringID, unix.KEY_SPEC_THREAD_KEYRING); err != nil {
		return nil, err
	}
	defer keyringUnlink(privilegedUserKeyringID, unix.KEY_SPEC_THREAD_KEYRING)

	// Drop euid last so we have permissions to drop the others.
	if err = unix.Setregid(-1, egid); err != nil {
		return nil, errors.Wrapf(err, "dropping egid to %d", egid)
	}
	if err = unix.Setgroups([]int{egid}); err != nil {
		return nil, errors.Wrapf(err, "dropping groups")
	}
	if err = unix.Setreuid(-1, euid); err != nil {
		return nil, errors.Wrapf(err, "dropping euid to %d", euid)
	}
	log.Printf("privileges dropped to euid=%d, egid=%d", euid, egid)

	// If the link already exists, this linking does nothing and succeeds.
	droppedUserKeyringID, err := getUserKeyringID()
	if err != nil {
		return nil, err
	}
	if err = keyringLink(droppedUserKeyringID, privilegedUserKeyringID); err != nil {
		return nil, err
	}
	log.Printf("user keyring (%d) linked into root user keyring (%d)",
		droppedUserKeyringID, privilegedUserKeyringID)

	return privs, nil
}

// RaiseThreadPrivileges returns the state of a threads privileges to what it
// was before the call to DropThreadPrivileges.
func RaiseThreadPrivileges(privs *Privileges) error {
	// Raise euid last so we have permissions to raise the others.
	if err := unix.Setreuid(-1, privs.euid); err != nil {
		return errors.Wrapf(err, "raising euid to %d", privs.euid)
	}
	if err := unix.Setregid(-1, privs.egid); err != nil {
		return errors.Wrapf(err, "raising egid to %d", privs.egid)
	}
	if err := unix.Setgroups(privs.groups); err != nil {
		return errors.Wrapf(err, "raising groups")
	}

	log.Printf("privileges raised to euid=%d, egid=%d", privs.euid, privs.egid)
	return nil
}

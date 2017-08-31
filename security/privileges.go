/*
 * privileges.go - Functions for managing users and privileges.
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
//  - Cache clearing (cache.go)
//  - Keyring Operations (keyring.go)
//  - Privilege manipulation (privileges.go)
//  - Maintaining the link between the root and user keyrings.
package security

import (
	"log"
	"os/user"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/util"
)

// SetThreadPrivileges drops drops the privileges of the current thread to have
// the uid/gid of the target user. If permanent is true, this operation cannot
// be reversed in the thread (the real and effective IDs are set). If
// permanent is false, only the effective IDs are set, allowing the privileges
// to be changed again with another call to SetThreadPrivileges.
func SetThreadPrivileges(target *user.User, permanent bool) error {
	euid := util.AtoiOrPanic(target.Uid)
	egid := util.AtoiOrPanic(target.Gid)
	var ruid, rgid int
	if permanent {
		log.Printf("Permanently dropping to user %q", target.Username)
		ruid, rgid = euid, egid
	} else {
		log.Printf("Temporarily dropping to user %q", target.Username)
		// Real IDs of -1 mean they will not be changed.
		ruid, rgid = -1, -1
	}

	// If setting privs to root, we want to set the uid first, so we will
	// then have the necessary permissions to perform the other actions.
	if euid == 0 {
		if err := setUids(ruid, euid); err != nil {
			return err
		}
	}

	if err := setGids(rgid, egid); err != nil {
		return err
	}

	if err := setGroups(target); err != nil {
		return err
	}

	// If not setting privs to root, we want to avoid dropping the uid
	// util the very end.
	if euid != 0 {
		if err := setUids(ruid, euid); err != nil {
			return err
		}
	}
	return nil
}

func setUids(ruid, euid int) error {
	err := unix.Setreuid(ruid, euid)
	log.Printf("Setreuid(%d, %d) = %v", ruid, euid, err)
	return errors.Wrapf(err, "setting uids")
}

func setGids(rgid, egid int) error {
	err := unix.Setregid(rgid, egid)
	log.Printf("Setregid(%d, %d) = %v", rgid, egid, err)
	return errors.Wrapf(err, "setting gids")
}

func setGroups(target *user.User) error {
	groupStrings, err := target.GroupIds()
	if err != nil {
		return util.SystemError(err.Error())
	}

	gids := make([]int, len(groupStrings))
	for i, groupString := range groupStrings {
		gids[i] = util.AtoiOrPanic(groupString)
	}

	err = unix.Setgroups(gids)
	log.Printf("Setgroups(%v) = %v", gids, err)
	return errors.Wrapf(err, "setting groups")
}

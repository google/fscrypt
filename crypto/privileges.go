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

package crypto

import (
	"log"
	"os"
	"os/user"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/util"
)

// SetThreadPrivileges temporarily drops the privileges of the current thread to
// have the effective uid/gid of the target user. The privileges can be changed
// again with another call to SetThreadPrivileges.
func SetThreadPrivileges(target *user.User) error {
	euid := util.AtoiOrPanic(target.Uid)
	egid := util.AtoiOrPanic(target.Gid)
	if os.Geteuid() == euid {
		log.Printf("Privileges already set to %q", target.Username)
		return nil
	}
	log.Printf("Setting privileges to %q", target.Username)

	// If setting privs to root, we want to set the uid first, so we will
	// then have the necessary permissions to perform the other actions.
	if euid == 0 {
		if err := setUids(-1, euid); err != nil {
			return err
		}
	}
	if err := setGids(-1, egid); err != nil {
		return err
	}
	if err := setGroups(target); err != nil {
		return err
	}
	// If not setting privs to root, we want to avoid dropping the uid
	// util the very end.
	if euid != 0 {
		if err := setUids(-1, euid); err != nil {
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

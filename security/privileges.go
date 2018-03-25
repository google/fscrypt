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

// Use the libc versions of setreuid, setregid, and setgroups instead of the
// "sys/unix" versions.  The "sys/unix" versions use the raw syscalls which
// operate on the calling thread only, whereas the libc versions operate on the
// whole process.  And we need to operate on the whole process, firstly for
// pam_fscrypt to prevent the privileges of Go worker threads from diverging
// from the PAM stack's "main" thread, violating libc's assumption and causing
// an abort() later in the PAM stack; and secondly because Go code may migrate
// between OS-level threads while it's running.
//
// See also: https://github.com/golang/go/issues/1435
//
// Also we need to wrap the libc functions in our own C functions rather than
// calling them directly because in the glibc headers (but not necessarily in
// the headers for other C libraries that may be used on Linux) they are
// declared to take __uid_t and __gid_t arguments rather than uid_t and gid_t.
// And while these are typedef'ed to the same underlying type, before Go 1.10,
// cgo maps them to different Go types.

/*
#include <sys/types.h>
#include <unistd.h>	// setreuid, setregid
#include <grp.h>	// setgroups

static int my_setreuid(uid_t ruid, uid_t euid)
{
	return setreuid(ruid, euid);
}

static int my_setregid(gid_t rgid, gid_t egid)
{
	return setregid(rgid, egid);
}

static int my_setgroups(size_t size, const gid_t *list)
{
	return setgroups(size, list);
}
*/
import "C"

import (
	"log"
	"os"
	"os/user"
	"syscall"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/util"
)

// SetProcessPrivileges temporarily drops the privileges of the current process
// to have the effective uid/gid of the target user. The privileges can be
// changed again with another call to SetProcessPrivileges.
func SetProcessPrivileges(target *user.User) error {
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
	res, err := C.my_setreuid(C.uid_t(ruid), C.uid_t(euid))
	log.Printf("setreuid(%d, %d) = %d (errno %v)", ruid, euid, res, err)
	if res == 0 {
		return nil
	}
	return errors.Wrapf(err.(syscall.Errno), "setting uids")
}

func setGids(rgid, egid int) error {
	res, err := C.my_setregid(C.gid_t(rgid), C.gid_t(egid))
	log.Printf("setregid(%d, %d) = %d (errno %v)", rgid, egid, res, err)
	if res == 0 {
		return nil
	}
	return errors.Wrapf(err.(syscall.Errno), "setting gids")
}

func setGroups(target *user.User) error {
	groupStrings, err := target.GroupIds()
	if err != nil {
		return util.SystemError(err.Error())
	}
	gids := make([]C.gid_t, len(groupStrings))
	for i, groupString := range groupStrings {
		gids[i] = C.gid_t(util.AtoiOrPanic(groupString))
	}
	res, err := C.my_setgroups(C.size_t(len(groupStrings)), &gids[0])
	log.Printf("setgroups(%v) = %d (errno %v)", gids, res, err)
	if res == 0 {
		return nil
	}
	return errors.Wrapf(err.(syscall.Errno), "setting groups")
}

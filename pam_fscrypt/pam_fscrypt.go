/*
 * pam_fscrypt.go - Checks the validity of a login token key against PAM.
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

package main

/*
#cgo LDFLAGS: -lpam -fPIC

#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
*/
import "C"
import (
	"log"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/pam"
	"github.com/google/fscrypt/security"
)

const (
	moduleName = "pam_fscrypt"
	// authtokLabel tags the AUTHTOK in the PAM data.
	authtokLabel = "fscrypt_authtok"
	// These flags are used to toggle behavior of the PAM module.
	debugFlag = "debug"
	lockFlag  = "lock_policies"
	cacheFlag = "drop_caches"
)

// Authenticate copies the AUTHTOK (if necessary) into the PAM data so it can be
// used in pam_sm_open_session.
func Authenticate(handle *pam.Handle, _ map[string]bool) error {
	if err := handle.DropThreadPrivileges(); err != nil {
		return err
	}
	defer handle.RaiseThreadPrivileges()

	// If this user doesn't have a login protector, no unlocking is needed.
	if _, err := loginProtector(handle); err != nil {
		log.Printf("no need to copy AUTHTOK: %s", err)
		return nil
	}

	log.Print("Authenticate: copying AUTHTOK for use in the session")
	authtok, err := handle.GetItem(pam.Authtok)
	if err != nil {
		return errors.Wrap(err, "could not get AUTHTOK")
	}
	err = handle.SetSecret(authtokLabel, authtok)
	return errors.Wrap(err, "could not set AUTHTOK data")
}

// OpenSession provisions any policies protected with the login protector.
func OpenSession(handle *pam.Handle, _ map[string]bool) error {
	// We will always clear the the AUTHTOK data
	defer handle.ClearData(authtokLabel)
	// Increment the count as we add a session
	if _, err := AdjustCount(handle, 1); err != nil {
		return err
	}

	if err := handle.DropThreadPrivileges(); err != nil {
		return err
	}
	defer handle.RaiseThreadPrivileges()

	// If there are no polices for the login protector, no unlocking needed.
	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("nothing to unlock: %s", err)
		return nil
	}
	policies := policiesUsingProtector(protector)
	if len(policies) == 0 {
		log.Print("no policies to unlock")
		return nil
	}

	log.Print("OpenSession: unlocking policies protected with AUTHTOK")
	keyFn := func(_ actions.ProtectorInfo, retry bool) (*crypto.Key, error) {
		if retry {
			// Login passphrase and login protector have diverged.
			// We could prompt the user for the old passphrase and
			// rewrap, but we currently don't.
			return nil, pam.ErrPassphrase
		}

		authtok, err := handle.GetSecret(authtokLabel)
		if err != nil {
			// pam_sm_authenticate was not run before the session is
			// opened. This can happen when a user does something
			// like "sudo su <user>". We could prompt for the
			// login passphrase here, but we currently don't.
			return nil, errors.Wrap(err, "AUTHTOK data missing")
		}

		return crypto.NewKeyFromCString(authtok)
	}
	if err := protector.Unlock(keyFn); err != nil {
		return errors.Wrapf(err, "unlocking protector %s", protector.Descriptor())
	}
	defer protector.Lock()

	// We don't stop provisioning polices on error, we try all of them.
	for _, policy := range policies {
		if policy.IsProvisioned() {
			log.Printf("policy %s already provisioned", policy.Descriptor())
			continue
		}
		if err := policy.UnlockWithProtector(protector); err != nil {
			log.Printf("unlocking policy %s: %s", policy.Descriptor(), err)
			continue
		}
		defer policy.Lock()

		if err := policy.Provision(); err != nil {
			log.Printf("provisioning policy %s: %s", policy.Descriptor(), err)
			continue
		}
		log.Printf("policy %s provisioned", policy.Descriptor())
	}
	return nil
}

// CloseSession can deprovision all keys provisioned at the start of the
// session. It can also clear the cache so these changes take effect.
func CloseSession(handle *pam.Handle, args map[string]bool) error {
	// Only do stuff on session close when we are the last session
	if count, err := AdjustCount(handle, -1); err != nil || count != 0 {
		return err
	}

	var errLock, errCache error
	// Don't automatically drop privileges, we may need them to drop caches.
	if args[lockFlag] {
		log.Print("CloseSession: locking polices protected with login")
		errLock = lockLoginPolicies(handle)
	}

	if args[cacheFlag] {
		log.Print("CloseSession: dropping inode caches")
		errCache = security.DropInodeCache()
	}

	if errLock != nil {
		return errLock
	}
	return errCache
}

// lockLoginPolicies deprovisions all policy keys that are protected by
// the user's login protector.
func lockLoginPolicies(handle *pam.Handle) error {
	if err := handle.DropThreadPrivileges(); err != nil {
		return err
	}
	defer handle.RaiseThreadPrivileges()

	// If there are no polices for the login protector, no locking needed.
	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("nothing to lock: %s", err)
		return nil
	}
	policies := policiesUsingProtector(protector)
	if len(policies) == 0 {
		log.Print("no policies to lock")
		return nil
	}

	// We will try to deprovision all of the policies.
	for _, policy := range policies {
		if !policy.IsProvisioned() {
			log.Printf("policy %s not provisioned", policy.Descriptor())
			continue
		}
		if err := policy.Deprovision(); err != nil {
			log.Printf("deprovisioning policy %s: %s", policy.Descriptor(), err)
			continue
		}
		log.Printf("policy %s deprovisioned", policy.Descriptor())
	}
	return nil
}

// Chauthtok rewraps the login protector when the passphrase changes.
func Chauthtok(handle *pam.Handle, _ map[string]bool) error {
	if err := handle.DropThreadPrivileges(); err != nil {
		return err
	}
	defer handle.RaiseThreadPrivileges()

	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("nothing to rewrap: %s", err)
		return nil
	}

	oldKeyFn := func(_ actions.ProtectorInfo, retry bool) (*crypto.Key, error) {
		if retry {
			// If the OLDAUTHTOK disagrees with the login protector,
			// we do nothing, as the protector will (probably) still
			// disagree after the login passphrase changes.
			return nil, pam.ErrPassphrase
		}
		authtok, err := handle.GetItem(pam.Oldauthtok)
		if err != nil {
			return nil, errors.Wrap(err, "could not get OLDAUTHTOK")
		}
		return crypto.NewKeyFromCString(authtok)
	}

	newKeyFn := func(_ actions.ProtectorInfo, _ bool) (*crypto.Key, error) {
		authtok, err := handle.GetItem(pam.Authtok)
		if err != nil {
			return nil, errors.Wrap(err, "could not get AUTHTOK")
		}
		return crypto.NewKeyFromCString(authtok)
	}

	log.Print("Chauthtok: rewrapping login protector")
	if err = protector.Unlock(oldKeyFn); err != nil {
		return err
	}
	defer protector.Lock()

	return protector.Rewrap(newKeyFn)
}

//export pam_sm_authenticate
func pam_sm_authenticate(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return RunPamFunc(Authenticate, pamh, argc, argv)
}

// pam_sm_stecred needed because we use pam_sm_authenticate.
//export pam_sm_setcred
func pam_sm_setcred(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return C.PAM_SUCCESS
}

//export pam_sm_open_session
func pam_sm_open_session(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return RunPamFunc(OpenSession, pamh, argc, argv)
}

//export pam_sm_close_session
func pam_sm_close_session(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return RunPamFunc(CloseSession, pamh, argc, argv)
}

//export pam_sm_chauthtok
func pam_sm_chauthtok(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	// Only do rewrapping if we have both AUTHTOKs and a login protector.
	if pam.Flag(flags)&pam.PrelimCheck != 0 {
		log.Print("no preliminary checks need to run")
		return C.PAM_SUCCESS
	}

	return RunPamFunc(Chauthtok, pamh, argc, argv)
}

// main() is needed to make a shared library compile
func main() {}

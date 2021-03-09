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
	"github.com/google/fscrypt/keyring"
	"github.com/google/fscrypt/pam"
	"github.com/google/fscrypt/security"
)

const (
	moduleName = "pam_fscrypt"
	// authtokLabel tags the AUTHTOK in the PAM data.
	authtokLabel = "fscrypt_authtok"
	// These flags are used to toggle behavior of the PAM module.
	debugFlag = "debug"

	// This option is accepted for compatibility with existing config files,
	// but now we lock policies unconditionally and this option is a no-op.
	lockPoliciesFlag = "lock_policies"

	// This option is accepted for compatibility with existing config files,
	// but it no longer does anything.  pam_fscrypt now drops caches if and
	// only if it is needed.  (Usually it is not needed anymore, as the
	// FS_IOC_REMOVE_ENCRYPTION_KEY ioctl handles this automatically.)
	dropCachesFlag = "drop_caches"
)

var (
	// PamFuncs for our 4 provided methods
	authenticateFunc = PamFunc{"Authenticate", Authenticate}
	openSessionFunc  = PamFunc{"OpenSession", OpenSession}
	closeSessionFunc = PamFunc{"CloseSession", CloseSession}
	chauthtokFunc    = PamFunc{"Chauthtok", Chauthtok}
)

// Authenticate copies the AUTHTOK (if necessary) into the PAM data so it can be
// used in pam_sm_open_session.
func Authenticate(handle *pam.Handle, _ map[string]bool) error {
	if err := handle.StartAsPamUser(); err != nil {
		return err
	}
	defer handle.StopAsPamUser()

	// If this user doesn't have a login protector, no unlocking is needed.
	if _, err := loginProtector(handle); err != nil {
		log.Printf("no protector, no need for AUTHTOK: %s", err)
		return nil
	}

	log.Print("copying AUTHTOK for use in the session open")
	authtok, err := handle.GetItem(pam.Authtok)
	if err != nil {
		return errors.Wrap(err, "could not get AUTHTOK")
	}
	err = handle.SetSecret(authtokLabel, authtok)
	return errors.Wrap(err, "could not set AUTHTOK data")
}

func beginProvisioningOp(handle *pam.Handle, policy *actions.Policy) error {
	if policy.NeedsRootToProvision() {
		return handle.StopAsPamUser()
	}
	return nil
}

func endProvisioningOp(handle *pam.Handle, policy *actions.Policy) error {
	if policy.NeedsRootToProvision() {
		return handle.StartAsPamUser()
	}
	return nil
}

// Set up the PAM user's keyring if needed by any encryption policies.
func setupUserKeyringIfNeeded(handle *pam.Handle, policies []*actions.Policy) error {
	needed := false
	for _, policy := range policies {
		if policy.NeedsUserKeyring() {
			needed = true
			break
		}
	}
	if !needed {
		return nil
	}
	err := handle.StopAsPamUser()
	if err != nil {
		return err
	}
	_, err = keyring.UserKeyringID(handle.PamUser, true)
	if err != nil {
		log.Printf("Setting up keyrings in PAM: %v", err)
	}
	return handle.StartAsPamUser()
}

// OpenSession provisions any policies protected with the login protector.
func OpenSession(handle *pam.Handle, _ map[string]bool) error {
	// We will always clear the AUTHTOK data
	defer handle.ClearData(authtokLabel)
	// Increment the count as we add a session
	if _, err := AdjustCount(handle, +1); err != nil {
		return err
	}

	if err := handle.StartAsPamUser(); err != nil {
		return err
	}
	defer handle.StopAsPamUser()

	// If there are no polices for the login protector, no unlocking needed.
	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("no protector to unlock: %s", err)
		return nil
	}
	policies := policiesUsingProtector(protector)
	if len(policies) == 0 {
		log.Print("no policies to unlock")
		return nil
	}

	if err = setupUserKeyringIfNeeded(handle, policies); err != nil {
		return errors.Wrapf(err, "setting up user keyring")
	}

	log.Printf("unlocking %d policies protected with AUTHTOK", len(policies))
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
		if policy.IsProvisionedByTargetUser() {
			log.Printf("policy %s already provisioned by %v",
				policy.Descriptor(), handle.PamUser.Username)
			continue
		}
		if err := policy.UnlockWithProtector(protector); err != nil {
			log.Printf("unlocking policy %s: %s", policy.Descriptor(), err)
			continue
		}
		defer policy.Lock()

		if err := beginProvisioningOp(handle, policy); err != nil {
			return err
		}
		provisionErr := policy.Provision()
		if err := endProvisioningOp(handle, policy); err != nil {
			return err
		}
		if provisionErr != nil {
			log.Printf("provisioning policy %s: %s", policy.Descriptor(), provisionErr)
			continue
		}
		log.Printf("policy %s provisioned by %v", policy.Descriptor(),
			handle.PamUser.Username)
	}
	return nil
}

// CloseSession can deprovision all keys provisioned at the start of the
// session. It can also clear the cache so these changes take effect.
func CloseSession(handle *pam.Handle, args map[string]bool) error {
	// Only do stuff on session close when we are the last session
	if count, err := AdjustCount(handle, -1); err != nil || count != 0 {
		log.Printf("count is %d and we are not locking", count)
		return err
	}

	if args[lockPoliciesFlag] {
		log.Print("ignoring deprecated 'lock_policies' option (now the default)")
	}

	if args[dropCachesFlag] {
		log.Print("ignoring deprecated 'drop_caches' option (now auto-detected)")
	}

	// Don't automatically drop privileges, since we may need them to
	// deprovision policies or to drop caches.

	log.Print("locking policies protected with login protector")
	needDropCaches, errLock := lockLoginPolicies(handle)

	var errCache error
	if needDropCaches {
		log.Print("dropping appropriate filesystem caches at session close")
		errCache = security.DropFilesystemCache()
	}

	if errLock != nil {
		return errLock
	}
	return errCache
}

// lockLoginPolicies deprovisions all policy keys that are protected by the
// user's login protector.  It returns true if dropping filesystem caches will
// be needed afterwards to completely lock the relevant directories.
func lockLoginPolicies(handle *pam.Handle) (bool, error) {
	needDropCaches := false

	if err := handle.StartAsPamUser(); err != nil {
		return needDropCaches, err
	}
	defer handle.StopAsPamUser()

	// If there are no polices for the login protector, no locking needed.
	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("nothing to lock: %s", err)
		return needDropCaches, nil
	}
	policies := policiesUsingProtector(protector)
	if len(policies) == 0 {
		log.Print("no policies to lock")
		return needDropCaches, nil
	}

	if err = setupUserKeyringIfNeeded(handle, policies); err != nil {
		return needDropCaches, errors.Wrapf(err, "setting up user keyring")
	}

	// We will try to deprovision all of the policies.
	for _, policy := range policies {
		if !policy.IsProvisionedByTargetUser() {
			log.Printf("policy %s not provisioned by %v",
				policy.Descriptor(), handle.PamUser.Username)
			continue
		}
		if policy.NeedsUserKeyring() {
			needDropCaches = true
		}
		if err := beginProvisioningOp(handle, policy); err != nil {
			return needDropCaches, err
		}
		deprovisionErr := policy.Deprovision(false)
		if err := endProvisioningOp(handle, policy); err != nil {
			return needDropCaches, err
		}
		if deprovisionErr != nil {
			log.Printf("deprovisioning policy %s: %s", policy.Descriptor(), deprovisionErr)
			continue
		}
		log.Printf("policy %s deprovisioned by %v", policy.Descriptor(), handle.PamUser.Username)
	}
	return needDropCaches, nil
}

// Chauthtok rewraps the login protector when the passphrase changes.
func Chauthtok(handle *pam.Handle, _ map[string]bool) error {
	if err := handle.StartAsPamUser(); err != nil {
		return err
	}
	defer handle.StopAsPamUser()

	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("no login protector to rewrap: %s", err)
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

	log.Print("rewrapping login protector")
	if err = protector.Unlock(oldKeyFn); err != nil {
		return err
	}
	defer protector.Lock()

	return protector.Rewrap(newKeyFn)
}

//export pam_sm_authenticate
func pam_sm_authenticate(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return authenticateFunc.Run(pamh, argc, argv)
}

// pam_sm_setcred needed because we use pam_sm_authenticate.
//export pam_sm_setcred
func pam_sm_setcred(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return C.PAM_SUCCESS
}

//export pam_sm_open_session
func pam_sm_open_session(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return openSessionFunc.Run(pamh, argc, argv)
}

//export pam_sm_close_session
func pam_sm_close_session(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return closeSessionFunc.Run(pamh, argc, argv)
}

//export pam_sm_chauthtok
func pam_sm_chauthtok(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	// Only do rewrapping if we have both AUTHTOKs and a login protector.
	if pam.Flag(flags)&pam.PrelimCheck != 0 {
		return C.PAM_SUCCESS
	}
	return chauthtokFunc.Run(pamh, argc, argv)
}

// main() is needed to make a shared library compile
func main() {}

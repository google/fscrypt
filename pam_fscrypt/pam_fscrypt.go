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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/pam"
	"github.com/google/fscrypt/security"
	"github.com/google/fscrypt/util"
)

const (
	moduleName = "pam_fscrypt"
	// These labels are used to tag items in the PAM data.
	authtokLabel    = "fscrypt_authtok"
	descriptorLabel = "fscrypt_descriptor"
	// These flags are used to toggle behavior of the PAM module.
	debugFlag = "debug"
	lockFlag  = "lock_policies"
	cacheFlag = "drop_caches"
)

// parseArgs takes a list of C arguments into a PAM function and returns a map
// where a key has a value of true if it appears in the argument list.
func parseArgs(argc C.int, argv **C.char) map[string]bool {
	args := make(map[string]bool)
	for _, cString := range util.PointerSlice(unsafe.Pointer(argv))[:argc] {
		args[C.GoString((*C.char)(cString))] = true
	}
	return args
}

// setupLogging directs turns off standard logging (or redirects it to debug
// syslog if the "debug" argument is passed) and returns a writer to the error
// syslog.
func setupLogging(args map[string]bool) io.Writer {
	log.SetFlags(0) // Syslog already includes time data itself
	log.SetOutput(ioutil.Discard)
	if args[debugFlag] {
		debugWriter, err := syslog.New(syslog.LOG_DEBUG, moduleName)
		if err == nil {
			log.SetOutput(debugWriter)
		}
	}

	errorWriter, err := syslog.New(syslog.LOG_ERR, moduleName)
	if err != nil {
		return ioutil.Discard
	}
	return errorWriter
}

// loginProtector returns the login protector corresponding to the PAM_USER if
// one exists. This protector descriptor (if found) will be cached in the pam
// data, under descriptorLabel.
func loginProtector(handle *pam.Handle) (*actions.Protector, error) {
	ctx, err := actions.NewContextFromMountpoint("/")
	if err != nil {
		return nil, err
	}

	// Find the user's PAM protector.
	uid := int64(unix.Geteuid())
	if err != nil {
		return nil, err
	}
	options, err := ctx.ProtectorOptions()
	if err != nil {
		return nil, err
	}
	for _, option := range options {
		if option.Source() == metadata.SourceType_pam_passphrase && option.UID() == uid {
			return actions.GetProtectorFromOption(ctx, option)
		}
	}
	return nil, fmt.Errorf("no PAM protector on %q", ctx.Mount.Path)
}

// pam_sm_authenticate copies the AUTHTOK (if necessary) into the PAM data so it
// can be used in pam_sm_open_session.
//export pam_sm_authenticate
func pam_sm_authenticate(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	errWriter := setupLogging(parseArgs(argc, argv))

	// If this user doesn't have a login protector, no unlocking is needed.
	if _, err := loginProtector(handle); err != nil {
		log.Printf("no need to copy AUTHTOK: %s", err)
		return C.PAM_SUCCESS
	}

	log.Print("copying AUTHTOK in pam_sm_authenticate()")
	authtok, err := handle.GetItem(pam.Authtok)
	if err != nil {
		fmt.Fprintf(errWriter, "could not get AUTHTOK: %s", err)
		return C.PAM_SERVICE_ERR
	}
	if err = handle.SetSecret(authtokLabel, authtok); err != nil {
		fmt.Fprintf(errWriter, "could not set AUTHTOK data: %s", err)
		return C.PAM_SERVICE_ERR
	}
	return C.PAM_SUCCESS
}

// pam_sm_stecred needed because we use pam_sm_authenticate.
//export pam_sm_setcred
func pam_sm_setcred(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return C.PAM_SUCCESS
}

// policiesUsingProtector searches all the mountpoints for any policies
// protected with the specified protector. An error during this search does not
// halt the search, instead the errors are written to errWriter.
func policiesUsingProtector(protector *actions.Protector, errWriter io.Writer) []*actions.Policy {
	mounts, err := filesystem.AllFilesystems()
	if err != nil {
		fmt.Fprint(errWriter, err)
		return nil
	}

	var policies []*actions.Policy
	for _, mount := range mounts {
		// Skip mountpoints that do not use the protector.
		if _, _, err := mount.GetProtector(protector.Descriptor()); err != nil {
			continue
		}
		policyDescriptors, err := mount.ListPolicies()
		if err != nil {
			fmt.Fprintf(errWriter, "listing policies: %s", err)
			continue
		}

		ctx := &actions.Context{Config: protector.Context.Config, Mount: mount}
		for _, policyDescriptor := range policyDescriptors {
			policy, err := actions.GetPolicy(ctx, policyDescriptor)
			if err != nil {
				fmt.Fprintf(errWriter, "reading policy: %s", err)
				continue
			}

			if policy.UsesProtector(protector) {
				policies = append(policies, policy)
			}
		}
	}
	return policies
}

// pam_sm_open_session provisions policies protected with the login protector.
//export pam_sm_open_session
func pam_sm_open_session(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	errWriter := setupLogging(parseArgs(argc, argv))

	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("no pam protector for this user: %s", err)
		return C.PAM_SUCCESS
	}

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
		defer handle.ClearData(authtokLabel)
		return crypto.NewKeyFromCString(authtok)
	}

	log.Print("searching for policies to unlock in pam_sm_open_session()")
	policies := policiesUsingProtector(protector, errWriter)
	if len(policies) == 0 {
		log.Print("no policies to unlock")
		return C.PAM_SUCCESS
	}

	if err := protector.Unlock(keyFn); err != nil {
		fmt.Fprintf(errWriter, "unlocking protector %s: %s", protector.Descriptor(), err)
		return C.PAM_SERVICE_ERR
	}
	defer protector.Lock()

	for _, policy := range policies {
		if policy.IsProvisioned() {
			log.Printf("policy %s already provisioned", policy.Descriptor())
			continue
		}
		if err := policy.UnlockWithProtector(protector); err != nil {
			fmt.Fprintf(errWriter, "unlocking policy %s: %s", policy.Descriptor(), err)
			continue
		}
		defer policy.Lock()

		if err := policy.Provision(); err != nil {
			fmt.Fprintf(errWriter, "provisioning policy %s: %s", policy.Descriptor(), err)
			continue
		}

		log.Printf("policy %s provisioned", policy.Descriptor())
	}

	return C.PAM_SUCCESS
}

// pam_sm_close_session deprovisions all keys provisioned at the start of the
// session. It also clears the cache so these changes take effect.
//export pam_sm_close_session
func pam_sm_close_session(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	args := parseArgs(argc, argv)
	errWriter := setupLogging(args)

	if args[lockFlag] {
		protector, err := loginProtector(handle)
		if err != nil {
			log.Printf("no pam protector for this user: %s", err)
			return C.PAM_SUCCESS
		}

		policies := policiesUsingProtector(protector, errWriter)

		if len(policies) == 0 {
			log.Print("no policies to lock")
			return C.PAM_SUCCESS
		}
	}

	log.Print("locking directories in pam_sm_close_session()")
	for _, provisionedKey := range provisionedKeys {
		if err := security.RemoveKey(provisionedKey); err != nil {
			fmt.Fprintf(errWriter, "can't remove %s: %s", provisionedKey, err)
		}
	}

	if args[cacheFlag] {
		if err = security.DropInodeCache(); err != nil {
			fmt.Fprint(errWriter, err)
			return C.PAM_SERVICE_ERR
		}
	}

	return C.PAM_SUCCESS
}

// pam_sm_chauthtok rewraps the login protector when the passphrase changes.
//export pam_sm_chauthtok
func pam_sm_chauthtok(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	errWriter := setupLogging(parseArgs(argc, argv))

	// Only do rewrapping if we have both AUTHTOKs and a login protector.
	if pam.Flag(flags)&pam.PrelimCheck != 0 {
		log.Print("no preliminary checks need to run")
		return C.PAM_SUCCESS
	}
	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("no protector to rewrap: %s", err)
		return C.PAM_SUCCESS
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

	log.Print("rewrapping protector in pam_sm_chauthtok()")
	if err = protector.Unlock(oldKeyFn); err != nil {
		fmt.Fprint(errWriter, err)
		return C.PAM_SERVICE_ERR
	}
	defer protector.Lock()
	if err = protector.Rewrap(newKeyFn); err != nil {
		fmt.Fprint(errWriter, err)
		return C.PAM_SERVICE_ERR
	}

	return C.PAM_SUCCESS
}

// main() is needed to make a shared library compile
func main() {}

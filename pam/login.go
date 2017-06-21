/*
 * login.go - Checks the validity of a login token key against PAM.
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

// Package pam contains all the functionality for interfacing with Linux
// Pluggable Authentication Modules (PAM). Currently, all this package does is
// check the validity of a user's login passphrase.
// See http://www.linux-pam.org/Linux-PAM-html/ for more information.
package pam

/*
#cgo LDFLAGS: -lpam
#include <stdlib.h>
#include "pam.h"
*/
import "C"

import (
	"log"
	"sync"
	"unsafe"

	"github.com/pkg/errors"

	"fscrypt/crypto"
	"fscrypt/util"
)

// Global state is needed for the PAM callback, so we guard this function with a
// lock. tokenToCheck is only ever non-nil when loginLock is held.
var (
	ErrPamInternal = util.SystemError("internal pam error")
	loginLock      sync.Mutex
	tokenToCheck   *crypto.Key
)

// unexpectedMessage logs an error encountered in the PAM callback.
//export unexpectedMessage
func unexpectedMessage(msg *C.char) {
	log.Printf("pam encountered unexpected %q", C.GoString(msg))
}

// pamInput is run when the PAM module needs some input from the user. The
// message parameter is the prompt that would be displayed to the user.
//export pamInput
func pamInput(msg *C.char) *C.char {
	log.Printf("requesting secret data with %q", C.GoString(msg))

	// Memory for the key must be moved into a C string allocated by C.
	cLen := C.size_t(tokenToCheck.Len())
	cData := C.malloc(cLen + 1)

	// View the cData as a go slice
	goData := (*[1 << 30]byte)(cData)
	copy(goData[:cLen], tokenToCheck.UnsafeData())
	goData[cLen] = 0 // Null terminator
	return (*C.char)(cData)
}

// IsUserLoginToken returns true if the presented token is the user's login key,
// false if it is not their login key, and an error if this cannot be
// determined. Note that unless the currently running process is root, this
// check will only work for the user running this process.
func IsUserLoginToken(username string, token *crypto.Key) (_ bool, err error) {
	log.Printf("Checking login token for %s", username)
	// We require global state for the function. This function never takes
	// ownership of the token, so it is not responsible for wiping it.
	loginLock.Lock()
	tokenToCheck = token
	defer func() {
		tokenToCheck = nil
		loginLock.Unlock()
	}()

	cUsername := C.CString(username)
	defer C.free(unsafe.Pointer(cUsername))

	var conv C.struct_pam_conv
	var handle *C.struct_pam_handle
	C.pam_init(&conv)

	// Start the pam transaction with the desired conversation and handle.
	returnCode := C.pam_start(C.fscrypt_service, cUsername, &conv, &handle)
	if returnCode != C.PAM_SUCCESS {
		return false, errors.Wrapf(ErrPamInternal, "pam_start() = %d", returnCode)
	}

	defer func() {
		// End the PAM transaction, setting the error if appropriate.
		returnCode = C.pam_end(handle, returnCode)
		if returnCode != C.PAM_SUCCESS && err == nil {
			err = errors.Wrapf(ErrPamInternal, "pam_end() = %d", returnCode)
		}
	}()

	// Ask PAM to authenticate the token. We either get an answer or an error
	returnCode = C.pam_authenticate(handle, 0)
	switch returnCode {
	case C.PAM_SUCCESS:
		return true, nil
	case C.PAM_AUTH_ERR:
		return false, nil
	default:
		// PAM didn't give us an answer to the authentication question
		return false, errors.Wrapf(ErrPamInternal, "pam_authenticate() = %d", returnCode)
	}
}

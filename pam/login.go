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

import "C"

import (
	"fmt"
	"log"
	"sync"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/util"
)

// Pam error values
var (
	ErrPassphrase = errors.New("incorrect login passphrase")
)

// Global state is needed for the PAM callback, so we guard this function with a
// lock. tokenToCheck is only ever non-nil when tokenLock is held.
var (
	tokenLock    sync.Mutex
	tokenToCheck *crypto.Key
)

// userInput is run when the callback needs some input from the user. We prompt
// the user for information and return their answer. A return value of nil
// indicates an error occurred.
//
//export userInput
func userInput(prompt *C.char) *C.char {
	fmt.Print(C.GoString(prompt))
	input, err := util.ReadLine()
	if err != nil {
		log.Printf("getting input for PAM: %s", err)
		return nil
	}
	return C.CString(input)
}

// passphraseInput is run when the callback needs a passphrase from the user. We
// pass along the tokenToCheck without prompting. A return value of nil
// indicates an error occurred.
//
//export passphraseInput
func passphraseInput(prompt *C.char) *C.char {
	log.Printf("getting secret data for PAM: %q", C.GoString(prompt))
	if tokenToCheck == nil {
		log.Print("secret data requested multiple times")
		return nil
	}

	// Subsequent calls to passphrase input should fail
	input := (*C.char)(tokenToCheck.UnsafeToCString())
	tokenToCheck = nil
	return input
}

// IsUserLoginToken returns nil if the presented token is the user's login key,
// and returns an error otherwise. Note that unless we are currently running as
// root, this check will only work for the user running this process.
func IsUserLoginToken(username string, token *crypto.Key, quiet bool) error {
	log.Printf("Checking login token for %s", username)

	// We require global state for the function. This function never takes
	// ownership of the token, so it is not responsible for wiping it.
	tokenLock.Lock()
	tokenToCheck = token
	defer func() {
		tokenToCheck = nil
		tokenLock.Unlock()
	}()

	transaction, err := Start("fscrypt", username)
	if err != nil {
		return err
	}
	defer transaction.End()

	// Ask PAM to authenticate the token.
	authenticated, err := transaction.Authenticate(quiet)
	if err != nil {
		return err
	}

	if !authenticated {
		return ErrPassphrase
	}
	return nil
}

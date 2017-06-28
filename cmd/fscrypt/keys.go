/*
 * keys.go - Functions and readers for getting passphrases and raw keys via
 * the command line. Includes ability to hide the entered passphrase, or use a
 * raw key as input.
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

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/pam"
)

// The file descriptor for standard input
const stdinFd = 0

// actions.KeyFuncs for getting or creating cryptographic keys
var (
	// getting an existing key
	existingKeyFn = makeKeyFunc(true, false, "")
	// getting an existing key when changing passphrases
	oldExistingKeyFn = makeKeyFunc(true, false, "old ")
	// creating a new key
	createKeyFn = makeKeyFunc(false, true, "")
	// creating a new key when changing passphrases
	newCreateKeyFn = makeKeyFunc(false, true, "new ")
)

// passphraseReader is an io.Reader intended for terminal passphrase input. The
// struct is empty as the reader needs to maintain no internal state.
type passphraseReader struct{}

// Read gets input from the terminal until a newline is encountered. This read
// should be called with the maximum buffer size for the passphrase.
func (p passphraseReader) Read(buf []byte) (int, error) {
	// We read one byte at a time to handle backspaces
	position := 0
	for {
		if position == len(buf) {
			return position, ErrMaxPassphrase
		}
		if _, err := io.ReadFull(os.Stdin, buf[position:position+1]); err != nil {
			return position, err
		}
		switch buf[position] {
		case '\r', '\n':
			return position, io.EOF
		case 3, 4:
			return position, ErrCanceled
		case 8, 127:
			if position > 0 {
				position--
			}
		default:
			position++
		}
	}
}

// getPassphraseKey puts the terminal into raw mode for the entry of the user's
// passphrase into a key. If we are not reading from a terminal, just read into
// the passphrase into the key normally.
func getPassphraseKey(prompt string) (*crypto.Key, error) {
	if !quietFlag.Value {
		fmt.Printf(prompt)
	}

	// Only disable echo if stdin is actually a terminal.
	if terminal.IsTerminal(stdinFd) {
		state, err := terminal.MakeRaw(stdinFd)
		if err != nil {
			return nil, err
		}
		defer func() {
			terminal.Restore(stdinFd, state)
			fmt.Println() // To align input
		}()
	}

	return crypto.NewKeyFromReader(passphraseReader{})
}

// makeKeyFunc creates an actions.KeyFunc. This function customizes the KeyFunc
// to whether or not it supports retrying, whether it confirms the passphrase,
// and custom prefix for printing (if any).
func makeKeyFunc(supportRetry, shouldConfirm bool, prefix string) actions.KeyFunc {
	return func(info actions.ProtectorInfo, retry bool) (*crypto.Key, error) {
		log.Printf("KeyFunc(%s, %v)", formatInfo(info), retry)
		if retry {
			if !supportRetry {
				panic("this KeyFunc does not support retrying")
			}
			// Don't retry for non-interactive sessions
			if quietFlag.Value {
				return nil, ErrWrongKey
			}
			fmt.Println("Incorrect Passphrase")
		}

		switch info.Source() {
		case metadata.SourceType_pam_passphrase:
			prompt := fmt.Sprintf("Enter %slogin passphrase for %s: ",
				prefix, getUsername(info.UID()))
			key, err := getPassphraseKey(prompt)
			if err != nil {
				return nil, err
			}

			// To confirm, check that the passphrase is the user's
			// login passphrase.
			if shouldConfirm {
				username := getUsername(info.UID())
				ok, err := pam.IsUserLoginToken(username, key)
				if err != nil {
					key.Wipe()
					return nil, err
				}
				if !ok {
					key.Wipe()
					return nil, ErrPAMPassphrase
				}
			}
			return key, nil

		case metadata.SourceType_custom_passphrase:
			prompt := fmt.Sprintf("Enter %scustom passphrase for protector %q: ",
				prefix, info.Name())
			key, err := getPassphraseKey(prompt)
			if err != nil {
				return nil, err
			}

			// To confirm, make sure the user types the same
			// passphrase in again.
			if shouldConfirm && !quietFlag.Value {
				key2, err := getPassphraseKey("Confirm passphrase: ")
				if err != nil {
					key.Wipe()
					return nil, err
				}
				defer key2.Wipe()

				if !key.Equals(key2) {
					key.Wipe()
					return nil, ErrPassphraseMismatch
				}
			}
			return key, nil

		case metadata.SourceType_raw_key:
			// Only use prefixes with passphrase protectors.
			if prefix != "" {
				return nil, ErrNotPassphrase
			}
			prompt := fmt.Sprintf("Enter key file for protector %q: ", info.Name())
			// Raw keys use a file containing the key data.
			file, err := promptForKeyFile(prompt)
			if err != nil {
				return nil, err
			}
			defer file.Close()

			fileInfo, err := file.Stat()
			if err != nil {
				return nil, err
			}

			if fileInfo.Size() != metadata.InternalKeyLen {
				return nil, errors.Wrap(ErrKeyFileLength, file.Name())
			}
			return crypto.NewFixedLengthKeyFromReader(file, metadata.InternalKeyLen)

		default:
			return nil, ErrInvalidSource
		}
	}
}

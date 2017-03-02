/*
 * crypto.go - Cryptographic algorithms used by the rest of fscrypt.
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

// Package crypto manages all the cryptography for fscrypt. This includes:
//	- Key management (key.go)
//		- Securely holding keys in memory
//		- Inserting keys into the keyring
//	- Randomness (rand.go)
//	- Cryptographic algorithms (crypto.go)
//		- encryption (AES256-CTR)
//		- authentication (SHA256-based HMAC)
//		- key stretching (SHA256-based HKDF)
//		- key wrapping/unwrapping (Encrypt then MAC)
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/unix"

	"fscrypt/metadata"
	"fscrypt/util"
)

// Lengths for our keys and buffers used for crypto.
const (
	// We always use 256-bit keys internally (compared to 512-bit policy keys).
	InternalKeyLen = 32
	IVLen          = 16
	SaltLen        = 16
	// PolicyKeyLen is the length of all keys passed directly to the Keyring
	PolicyKeyLen = unix.FS_MAX_KEY_SIZE
)

// "name" has invalid length if expected != actual
func checkInputLength(name string, expected, actual int) {
	if expected != actual {
		util.NeverError(util.InvalidLengthError(name, expected, actual))
	}
}

// stretchKey stretches a key of length KeyLen using unsalted HKDF to make two
// keys of length KeyLen.
func stretchKey(key *Key) (encKey, authKey *Key) {
	checkInputLength("hkdf key", InternalKeyLen, key.Len())

	// The new hkdf function uses the hash and key to create a reader that
	// can be used to securely initialize multiple keys. This means that
	// reads on the hkdf give independent cryptographic keys. The hkdf will
	// also always have enough entropy to read two keys.
	hkdf := hkdf.New(sha256.New, key.data, nil, nil)

	encKey, err := NewFixedLengthKeyFromReader(hkdf, InternalKeyLen)
	util.NeverError(err)
	authKey, err = NewFixedLengthKeyFromReader(hkdf, InternalKeyLen)
	util.NeverError(err)

	return
}

// Runs AES256-CTR on the input using the provided key and iv. This function can
// be used to either encrypt or decrypt input of any size. Note that input and
// output must be the same size.
func aesCTR(key *Key, iv, input, output []byte) {
	checkInputLength("aesCTR key", InternalKeyLen, key.Len())
	checkInputLength("aesCTR iv", IVLen, len(iv))
	checkInputLength("aesCTR output", len(input), len(output))

	blockCipher, err := aes.NewCipher(key.data)
	util.NeverError(err) // Key is checked to have correct length

	stream := cipher.NewCTR(blockCipher, iv)
	stream.XORKeyStream(output, input)
}

// Get a HMAC (with a SHA256-based hash) of some data using the provided key.
func getHMAC(key *Key, data ...[]byte) []byte {
	checkInputLength("hmac key", InternalKeyLen, key.Len())

	mac := hmac.New(sha256.New, key.data)
	for _, buffer := range data {
		// SHA256 HMAC should never be unable to write the data
		_, err := mac.Write(buffer)
		util.NeverError(err)
	}

	return mac.Sum(nil)
}

// Wrap takes a wrapping Key of length InternalKeyLen, and uses it to wrap a
// secret Key of any length. This wrapping uses a random IV, the encrypted data,
// and an HMAC to verify the wrapping key was correct. All of this is included
// in the returned WrappedKeyData structure.
func Wrap(wrappingKey, secretKey *Key) (*metadata.WrappedKeyData, error) {
	if wrappingKey.Len() != InternalKeyLen {
		return nil, util.InvalidLengthError("wrapping key", InternalKeyLen, wrappingKey.Len())
	}

	data := &metadata.WrappedKeyData{
		IV:           make([]byte, IVLen),
		EncryptedKey: make([]byte, secretKey.Len()),
	}

	// Get random IV
	if _, err := io.ReadFull(RandReader, data.IV); err != nil {
		return nil, err
	}

	// Stretch key for encryption and authentication (unsalted).
	encKey, authKey := stretchKey(wrappingKey)
	defer encKey.Wipe()
	defer authKey.Wipe()

	// Encrypt the secret and include the HMAC of the output ("Encrypt-then-MAC").
	aesCTR(encKey, data.IV, secretKey.data, data.EncryptedKey)

	data.Hmac = getHMAC(authKey, data.IV, data.EncryptedKey)
	return data, nil
}

// Unwrap takes a wrapping Key of length KeyLen, and uses it to unwrap the
// WrappedKeyData to get the unwrapped secret Key. The Wrapped Key data includes
// an authentication check, so an error will be returned if that check fails.
func Unwrap(wrappingKey *Key, data *metadata.WrappedKeyData) (*Key, error) {
	if wrappingKey.Len() != InternalKeyLen {
		return nil, util.InvalidLengthError("wrapping key", InternalKeyLen, wrappingKey.Len())
	}

	// Stretch key for encryption and authentication (unsalted).
	encKey, authKey := stretchKey(wrappingKey)
	defer encKey.Wipe()
	defer authKey.Wipe()

	// Check validity of the HMAC
	if !hmac.Equal(getHMAC(authKey, data.IV, data.EncryptedKey), data.Hmac) {
		return nil, fmt.Errorf("key authentication check failed")
	}

	secretKey, err := newBlankKey(len(data.EncryptedKey))
	if err != nil {
		return nil, err
	}
	aesCTR(encKey, data.IV, data.EncryptedKey, secretKey.data)

	return secretKey, nil
}

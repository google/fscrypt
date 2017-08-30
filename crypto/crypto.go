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
//		- Making recovery keys
//	- Randomness (rand.go)
//	- Cryptographic algorithms (crypto.go)
//		- encryption (AES256-CTR)
//		- authentication (SHA256-based HMAC)
//		- key stretching (SHA256-based HKDF)
//		- key wrapping/unwrapping (Encrypt then MAC)
//		- passphrase-based key derivation (Argon2id)
//		- descriptor computation (double SHA512)
package crypto

/*
#cgo LDFLAGS: -largon2
#include <stdlib.h> // malloc(), free()
#include <argon2.h>
*/
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"

	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/util"
)

// Crypto error values
var (
	ErrBadAuth        = errors.New("key authentication check failed")
	ErrNegitiveLength = errors.New("keys cannot have negative lengths")
	ErrRecoveryCode   = errors.New("invalid recovery code")
	ErrGetrandomFail  = util.SystemError("getrandom() failed")
	ErrKeyAlloc       = util.SystemError("could not allocate memory for key")
	ErrKeyFree        = util.SystemError("could not free memory of key")
	ErrKeyLock        = errors.New("could not lock key in memory")
)

// panicInputLength panics if "name" has invalid length (expected != actual)
func panicInputLength(name string, expected, actual int) {
	if err := util.CheckValidLength(expected, actual); err != nil {
		panic(errors.Wrap(err, name))
	}
}

// checkWrappingKey returns an error if the wrapping key has the wrong length
func checkWrappingKey(wrappingKey *Key) error {
	err := util.CheckValidLength(metadata.InternalKeyLen, wrappingKey.Len())
	return errors.Wrap(err, "wrapping key")
}

// stretchKey stretches a key of length KeyLen using unsalted HKDF to make two
// keys of length KeyLen.
func stretchKey(key *Key) (encKey, authKey *Key) {
	panicInputLength("hkdf key", metadata.InternalKeyLen, key.Len())

	// The new hkdf function uses the hash and key to create a reader that
	// can be used to securely initialize multiple keys. This means that
	// reads on the hkdf give independent cryptographic keys. The hkdf will
	// also always have enough entropy to read two keys.
	hkdf := hkdf.New(sha256.New, key.data, nil, nil)

	encKey, err := NewFixedLengthKeyFromReader(hkdf, metadata.InternalKeyLen)
	util.NeverError(err)
	authKey, err = NewFixedLengthKeyFromReader(hkdf, metadata.InternalKeyLen)
	util.NeverError(err)

	return
}

// aesCTR runs AES256-CTR on the input using the provided key and iv. This
// function can be used to either encrypt or decrypt input of any size. Note
// that input and output must be the same size.
func aesCTR(key *Key, iv, input, output []byte) {
	panicInputLength("aesCTR key", metadata.InternalKeyLen, key.Len())
	panicInputLength("aesCTR iv", metadata.IVLen, len(iv))
	panicInputLength("aesCTR output", len(input), len(output))

	blockCipher, err := aes.NewCipher(key.data)
	util.NeverError(err) // Key is checked to have correct length

	stream := cipher.NewCTR(blockCipher, iv)
	stream.XORKeyStream(output, input)
}

// getHMAC returns the SHA256-based HMAC of some data using the provided key.
func getHMAC(key *Key, data ...[]byte) []byte {
	panicInputLength("hmac key", metadata.InternalKeyLen, key.Len())

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
	if err := checkWrappingKey(wrappingKey); err != nil {
		return nil, err
	}

	data := &metadata.WrappedKeyData{EncryptedKey: make([]byte, secretKey.Len())}

	// Get random IV
	var err error
	if data.IV, err = NewRandomBuffer(metadata.IVLen); err != nil {
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
	if err := checkWrappingKey(wrappingKey); err != nil {
		return nil, err
	}

	// Stretch key for encryption and authentication (unsalted).
	encKey, authKey := stretchKey(wrappingKey)
	defer encKey.Wipe()
	defer authKey.Wipe()

	// Check validity of the HMAC
	if !hmac.Equal(getHMAC(authKey, data.IV, data.EncryptedKey), data.Hmac) {
		return nil, ErrBadAuth
	}

	secretKey, err := newBlankKey(len(data.EncryptedKey))
	if err != nil {
		return nil, err
	}
	aesCTR(encKey, data.IV, data.EncryptedKey, secretKey.data)

	return secretKey, nil
}

// newArgon2Context creates an argon2_context C struct given the hash and
// passphrase keys, salt and costs. The structure must be freed by the caller.
func newArgon2Context(hash, passphrase *Key,
	salt []byte, costs *metadata.HashingCosts) *C.argon2_context {

	ctx := (*C.argon2_context)(C.malloc(C.sizeof_argon2_context))

	ctx.out = (*C.uint8_t)(util.Ptr(hash.data))
	ctx.outlen = C.uint32_t(hash.Len())

	ctx.pwd = (*C.uint8_t)(util.Ptr(passphrase.data))
	ctx.pwdlen = C.uint32_t(passphrase.Len())

	ctx.salt = (*C.uint8_t)(util.Ptr(salt))
	ctx.saltlen = C.uint32_t(len(salt))

	ctx.secret = nil // We don't use the secret field.
	ctx.secretlen = 0
	ctx.ad = nil // We don't use the associated data field.
	ctx.adlen = 0

	ctx.t_cost = C.uint32_t(costs.Time)
	ctx.m_cost = C.uint32_t(costs.Memory)
	ctx.lanes = C.uint32_t(costs.Parallelism)

	ctx.threads = ctx.lanes
	ctx.version = C.ARGON2_VERSION_13

	// We use the built in malloc/free for memory.
	ctx.allocate_cbk = nil
	ctx.free_cbk = nil
	ctx.flags = C.ARGON2_FLAG_CLEAR_PASSWORD

	return ctx
}

// ComputeDescriptor computes the descriptor for a given cryptographic key. In
// keeping with the process used in e4crypt, this uses the initial bytes
// (formatted as hexadecimal) of the double application of SHA512 on the key.
func ComputeDescriptor(key *Key) string {
	h1 := sha512.Sum512(key.data)
	h2 := sha512.Sum512(h1[:])
	length := hex.DecodedLen(metadata.DescriptorLen)
	return hex.EncodeToString(h2[:length])
}

/*
PassphraseHash uses Argon2id to produce a Key given the passphrase, salt, and
hashing costs. This method is designed to take a long time and consume
considerable memory. On success, passphrase will no longer have valid data.
However, the caller should still call passphrase.Wipe().

Argon2 is the winning algorithm of the Password Hashing Competition
(see: https://password-hashing.net). It is designed to be "memory hard"
in that a large amount of memory is required to compute the hash value.
This makes it hard to use specialized hardware like GPUs and ASICs. We
use it in "id" mode to provide extra protection against side-channel
attacks. For more info see: https://github.com/P-H-C/phc-winner-argon2
*/
func PassphraseHash(passphrase *Key, salt []byte, costs *metadata.HashingCosts) (*Key, error) {
	if err := util.CheckValidLength(metadata.SaltLen, len(salt)); err != nil {
		return nil, errors.Wrap(err, "passphrase hashing salt")
	}
	if err := costs.CheckValidity(); err != nil {
		return nil, errors.Wrap(err, "passphrase hashing costs")
	}

	// This key will hold the hashing output
	hash, err := newBlankKey(metadata.InternalKeyLen)
	if err != nil {
		return nil, err
	}

	ctx := newArgon2Context(hash, passphrase, salt, costs)
	defer C.free(unsafe.Pointer(ctx))

	// Run the hashing function (translating the error if there is one)
	returnCode := C.argon2id_ctx(ctx)
	if returnCode != C.ARGON2_OK {
		hash.Wipe()
		errorString := C.GoString(C.argon2_error_message(returnCode))
		return nil, util.SystemError("argon2: " + errorString)
	}

	return hash, nil
}

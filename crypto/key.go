/*
 * key.go - Cryptographic key management for fscrypt. Ensures that sensitive
 * material is properly handled throughout the program.
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

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"bytes"
	"crypto/subtle"
	"encoding/base32"
	"io"
	"log"
	"os"
	"os/user"
	"runtime"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/security"
	"github.com/google/fscrypt/util"
)

const (
	// Keys need to readable and writable, but hidden from other processes.
	keyProtection = unix.PROT_READ | unix.PROT_WRITE
	keyMmapFlags  = unix.MAP_PRIVATE | unix.MAP_ANONYMOUS
)

/*
UseMlock determines whether we should use the mlock/munlock syscalls to
prevent sensitive data like keys and passphrases from being paged to disk.
UseMlock defaults to true, but can be set to false if the application calling
into this library has insufficient privileges to lock memory. Code using this
package could also bind this setting to a flag by using:

	flag.BoolVar(&crypto.UseMlock, "lock-memory", true, "lock keys in memory")
*/
var UseMlock = true

/*
Key protects some arbitrary buffer of cryptographic material. Its methods
ensure that the Key's data is locked in memory before being used (if
UseMlock is set to true), and is wiped and unlocked after use (via the Wipe()
method). This data is never accessed outside of the fscrypt/crypto package
(except for the UnsafeData method). If a key is successfully created, the
Wipe() method should be called after it's use. For example:

	func UseKeyFromStdin() error {
		key, err := NewKeyFromReader(os.Stdin)
		if err != nil {
			return err
		}
		defer key.Wipe()

		// Do stuff with key

		return nil
	}

The Wipe() method will also be called when a key is garbage collected; however,
it is best practice to clear the key as soon as possible, so it spends a minimal
amount of time in memory.

Note that Key is not thread safe, as a key could be wiped while another thread
is using it. Also, calling Wipe() from two threads could cause an error as
memory could be freed twice.
*/
type Key struct {
	data []byte
}

// newBlankKey constructs a blank key of a specified length and returns an error
// if we are unable to allocate or lock the necessary memory.
func newBlankKey(length int) (*Key, error) {
	if length == 0 {
		return &Key{data: nil}, nil
	} else if length < 0 {
		return nil, errors.Wrapf(ErrNegitiveLength, "length of %d requested", length)
	}

	flags := keyMmapFlags
	if UseMlock {
		flags |= unix.MAP_LOCKED
	}

	// See MAP_ANONYMOUS in http://man7.org/linux/man-pages/man2/mmap.2.html
	data, err := unix.Mmap(-1, 0, length, keyProtection, flags)
	if err == unix.EAGAIN {
		return nil, ErrKeyLock
	}
	if err != nil {
		log.Printf("unix.Mmap() with length=%d failed: %v", length, err)
		return nil, ErrKeyAlloc
	}

	key := &Key{data: data}

	// Backup finalizer in case user forgets to "defer key.Wipe()"
	runtime.SetFinalizer(key, (*Key).Wipe)
	return key, nil
}

// Wipe destroys a Key by zeroing and freeing the memory. The data is zeroed
// even if Wipe returns an error, which occurs if we are unable to unlock or
// free the key memory. Wipe does nothing if the key is already wiped or is nil.
func (key *Key) Wipe() error {
	// We do nothing if key or key.data is nil so that Wipe() is idempotent
	// and so Wipe() can be called on keys which have already been cleared.
	if key != nil && key.data != nil {
		data := key.data
		key.data = nil

		for i := range data {
			data[i] = 0
		}

		if err := unix.Munmap(data); err != nil {
			log.Printf("unix.Munmap() failed: %v", err)
			return ErrKeyFree
		}
	}
	return nil
}

// Len is the underlying data buffer's length.
func (key *Key) Len() int {
	return len(key.data)
}

// Equals compares the contents of two keys, returning true if they have the same
// key data. This function runs in constant time.
func (key *Key) Equals(key2 *Key) bool {
	return subtle.ConstantTimeCompare(key.data, key2.data) == 1
}

// resize returns a new key with size requestedSize and the appropriate data
// copied over. The original data is wiped. This method does nothing and returns
// itself if the key's length equals requestedSize.
func (key *Key) resize(requestedSize int) (*Key, error) {
	if key.Len() == requestedSize {
		return key, nil
	}
	defer key.Wipe()

	resizedKey, err := newBlankKey(requestedSize)
	if err != nil {
		return nil, err
	}
	copy(resizedKey.data, key.data)
	return resizedKey, nil
}

// UnsafeToCString makes a copy of the string's data into a null-terminated C
// string allocated by C. Note that this method is unsafe as this C copy has no
// locking or wiping functionality. The key shouldn't contain any `\0` bytes.
func (key *Key) UnsafeToCString() unsafe.Pointer {
	size := C.size_t(key.Len())
	data := C.calloc(size+1, 1)
	C.memcpy(data, util.Ptr(key.data), size)
	return data
}

// NewKeyFromCString creates of a copy of some C string's data in a key. Note
// that the original C string is not modified at all, so steps must be taken to
// ensure that this original copy is secured.
func NewKeyFromCString(str unsafe.Pointer) (*Key, error) {
	size := C.strlen((*C.char)(str))
	key, err := newBlankKey(int(size))
	if err != nil {
		return nil, err
	}
	C.memcpy(util.Ptr(key.data), str, size)
	return key, nil
}

// NewKeyFromReader constructs a key of abritary length by reading from reader
// until hitting EOF.
func NewKeyFromReader(reader io.Reader) (*Key, error) {
	// Use an initial key size of a page. As Mmap allocates a page anyway,
	// there isn't much additional overhead from starting with a whole page.
	key, err := newBlankKey(os.Getpagesize())
	if err != nil {
		return nil, err
	}

	totalBytesRead := 0
	for {
		bytesRead, err := reader.Read(key.data[totalBytesRead:])
		totalBytesRead += bytesRead

		switch err {
		case nil:
			// Need to continue reading. Grow key if necessary
			if key.Len() == totalBytesRead {
				if key, err = key.resize(2 * key.Len()); err != nil {
					return nil, err
				}
			}
		case io.EOF:
			// Getting the EOF error means we are done
			return key.resize(totalBytesRead)
		default:
			// Fail if Read() has a failure
			key.Wipe()
			return nil, err
		}
	}
}

// NewFixedLengthKeyFromReader constructs a key with a specified length by
// reading exactly length bytes from reader.
func NewFixedLengthKeyFromReader(reader io.Reader, length int) (*Key, error) {
	key, err := newBlankKey(length)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(reader, key.data); err != nil {
		key.Wipe()
		return nil, err
	}
	return key, nil
}

// InsertPolicyKey puts the provided policy key into the kernel keyring with the
// provided description, and type logon. The key must be a policy key.
func InsertPolicyKey(key *Key, description string, target *user.User) error {
	if err := util.CheckValidLength(metadata.PolicyKeyLen, key.Len()); err != nil {
		return errors.Wrap(err, "policy key")
	}

	// Create our payload (containing an FscryptKey)
	payload, err := newBlankKey(int(unsafe.Sizeof(unix.FscryptKey{})))
	if err != nil {
		return err
	}
	defer payload.Wipe()

	// Cast the payload to an FscryptKey so we can initialize the fields.
	fscryptKey := (*unix.FscryptKey)(util.Ptr(payload.data))
	// Mode is ignored by the kernel
	fscryptKey.Mode = 0
	fscryptKey.Size = metadata.PolicyKeyLen
	copy(fscryptKey.Raw[:], key.data)

	return security.InsertKey(payload.data, description, target)
}

var (
	// The recovery code is base32 with a dash between each block of 8 characters.
	encoding      = base32.StdEncoding
	blockSize     = 8
	separator     = []byte("-")
	encodedLength = encoding.EncodedLen(metadata.PolicyKeyLen)
	decodedLength = encoding.DecodedLen(encodedLength)
	// RecoveryCodeLength is the number of bytes in every recovery code
	RecoveryCodeLength = (encodedLength/blockSize)*(blockSize+len(separator)) - len(separator)
)

// WriteRecoveryCode outputs key's recovery code to the provided writer.
// WARNING: This recovery key is enough to derive the original key, so it must
// be given the same level of protection as a raw cryptographic key.
func WriteRecoveryCode(key *Key, writer io.Writer) error {
	if err := util.CheckValidLength(metadata.PolicyKeyLen, key.Len()); err != nil {
		return errors.Wrap(err, "recovery key")
	}

	// We store the base32 encoded data (without separators) in a temp key
	encodedKey, err := newBlankKey(encodedLength)
	if err != nil {
		return err
	}
	defer encodedKey.Wipe()
	encoding.Encode(encodedKey.data, key.data)

	w := util.NewErrWriter(writer)

	// Write the blocks with separators between them
	w.Write(encodedKey.data[:blockSize])
	for blockStart := blockSize; blockStart < encodedLength; blockStart += blockSize {
		w.Write(separator)

		blockEnd := util.MinInt(blockStart+blockSize, encodedLength)
		w.Write(encodedKey.data[blockStart:blockEnd])
	}

	// If any writes have failed, return the error
	return w.Err()
}

// ReadRecoveryCode gets the recovery code from the provided writer and returns
// the corresponding cryptographic key.
// WARNING: This recovery key is enough to derive the original key, so it must
// be given the same level of protection as a raw cryptographic key.
func ReadRecoveryCode(reader io.Reader) (*Key, error) {
	// We store the base32 encoded data (without separators) in a temp key
	encodedKey, err := newBlankKey(encodedLength)
	if err != nil {
		return nil, err
	}
	defer encodedKey.Wipe()

	r := util.NewErrReader(reader)

	// Read the other blocks, checking the separators between them
	r.Read(encodedKey.data[:blockSize])
	inputSeparator := make([]byte, len(separator))

	for blockStart := blockSize; blockStart < encodedLength; blockStart += blockSize {
		r.Read(inputSeparator)
		if r.Err() == nil && !bytes.Equal(separator, inputSeparator) {
			err = errors.Wrapf(ErrRecoveryCode, "invalid separator %q", inputSeparator)
			return nil, err
		}

		blockEnd := util.MinInt(blockStart+blockSize, encodedLength)
		r.Read(encodedKey.data[blockStart:blockEnd])
	}

	// If any reads have failed, return the error
	if r.Err() != nil {
		return nil, errors.Wrapf(ErrRecoveryCode, "read error %v", r.Err())
	}

	// Now we decode the key, resizing if necessary
	decodedKey, err := newBlankKey(decodedLength)
	if err != nil {
		return nil, err
	}
	if _, err = encoding.Decode(decodedKey.data, encodedKey.data); err != nil {
		return nil, errors.Wrap(ErrRecoveryCode, err.Error())
	}
	return decodedKey.resize(metadata.PolicyKeyLen)
}

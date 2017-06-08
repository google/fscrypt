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

import (
	"bytes"
	"crypto/subtle"
	"encoding/base32"
	"io"
	"log"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"

	"fscrypt/metadata"
	"fscrypt/util"
)

// Service Prefixes for keyring keys. As of kernel v4.8, all filesystems
// supporting encryption will use FS_KEY_DESC_PREFIX to indicate that a key in
// the keyring should be used with filesystem encryption. However, we also
// include the older service prefixes for legacy compatibility.
const (
	ServiceDefault = unix.FS_KEY_DESC_PREFIX
	// ServiceExt4 was used before v4.8 for ext4 filesystem encryption.
	ServiceExt4 = "ext4:"
	// ServiceExt4 was used before v4.6 for F2FS filesystem encryption.
	ServiceF2FS = "f2fs:"
	// keyType is always logon as required by filesystem encryption
	keyType = "logon"
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

const (
	// Keys need to readable and writable, but hidden from other processes.
	keyProtection = unix.PROT_READ | unix.PROT_WRITE
	keyMmapFlags  = unix.MAP_PRIVATE | unix.MAP_ANONYMOUS
)

// newBlankKey constructs a blank key of a specified length and returns an error
// if we are unable to allocate or lock the necessary memory.
func newBlankKey(length int) (*Key, error) {
	if length == 0 {
		return &Key{data: nil}, nil
	} else if length < 0 {
		log.Printf("key length of %d is invalid", length)
		return nil, ErrNegitiveLength
	}

	flags := keyMmapFlags
	if UseMlock {
		flags |= unix.MAP_LOCKED
	}

	// See MAP_ANONYMOUS in http://man7.org/linux/man-pages/man2/mmap.2.html
	data, err := unix.Mmap(-1, 0, length, keyProtection, flags)
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
// free the key memory. Calling Wipe() multiple times on a key has no effect.
func (key *Key) Wipe() error {
	if key.data != nil {
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

// UnsafeData exposes the underlying protected slice. This is unsafe because the
// data can be paged to disk if the buffer is copied, or the slice may be
// wiped while being used.
func (key *Key) UnsafeData() []byte {
	return key.data
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

// addPayloadToSessionKeyring adds the payload to the current session keyring as
// type logon, returning an error on failure.
func addPayloadToSessionKeyring(payload []byte, description string) error {
	// We cannot add directly to KEY_SPEC_SESSION_KEYRING, as that will make
	// a new session keyring if one does not exist, which will be garbage
	// collected when the process terminates. Instead, we first get the ID
	// of the KEY_SPEC_SESSION_KEYRING, which will return the user session
	// keyring if a session keyring does not exist.
	keyringID, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, false)
	log.Printf("unix.KeyctlGetKeyringID(KEY_SPEC_SESSION_KEYRING) = %d, %v", keyringID, err)
	if err != nil {
		return ErrKeyringLocate
	}

	keyID, err := unix.AddKey(keyType, description, payload, keyringID)
	log.Printf("unix.AddKey(%s, %s, <payload>, %d) = %d, %v",
		keyType, description, keyringID, keyID, err)
	if err != nil {
		return ErrKeyringInsert
	}
	return nil
}

// FindPolicyKey tries to locate a policy key in the kernel keyring with the
// provided descriptor and service. The key id is returned if we can find the
// key. An error is returned if the key does not exist.
func FindPolicyKey(descriptor, service string) (int, error) {
	description := service + descriptor
	keyID, err := unix.KeyctlSearch(unix.KEY_SPEC_SESSION_KEYRING, keyType, description, 0)
	log.Printf("unix.KeyctlSearch(KEY_SPEC_SESSION_KEYRING, %s, %s, 0) = %d, %v",
		keyType, description, keyID, err)
	if err != nil {
		return 0, ErrKeyringSearch
	}
	return keyID, nil
}

// RemovePolicyKey tries to remove a policy key from the kernel keyring with the
// provided descriptor and service. An error is returned if the key does not
// exist.
func RemovePolicyKey(descriptor, service string) error {
	keyID, err := FindPolicyKey(descriptor, service)
	if err != nil {
		return err
	}

	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, unix.KEY_SPEC_SESSION_KEYRING, 0, 0)
	log.Printf("unix.KeyctlUnlink(%d, KEY_SPEC_SESSION_KEYRING) = %v", keyID, err)
	if err != nil {
		return ErrKeyringDelete
	}
	return nil
}

// InsertPolicyKey puts the provided policy key into the kernel keyring with the
// provided descriptor, provided service prefix, and type logon. The key and
// descriptor must have the appropriate lengths.
func InsertPolicyKey(key *Key, descriptor, service string) error {
	if key.Len() != metadata.PolicyKeyLen {
		return util.InvalidLengthError("Policy Key", metadata.PolicyKeyLen, key.Len())
	}

	if len(descriptor) != metadata.DescriptorLen {
		return util.InvalidLengthError("Descriptor", metadata.DescriptorLen, len(descriptor))
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

	if err := addPayloadToSessionKeyring(payload.data, service+descriptor); err != nil {
		return err
	}

	return nil
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
	if key.Len() != metadata.PolicyKeyLen {
		return util.InvalidLengthError("key", metadata.PolicyKeyLen, key.Len())
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
			log.Printf("separator of %q is invalid", inputSeparator)
			return nil, ErrRecoveryCode
		}

		blockEnd := util.MinInt(blockStart+blockSize, encodedLength)
		r.Read(encodedKey.data[blockStart:blockEnd])
	}

	// If any reads have failed, return the error
	if r.Err() != nil {
		log.Printf("error while reading recovery code: %v", r.Err())
		return nil, ErrRecoveryCode
	}

	// Now we decode the key, resizing if necessary
	decodedKey, err := newBlankKey(decodedLength)
	if err != nil {
		return nil, err
	}
	if _, err = encoding.Decode(decodedKey.data, encodedKey.data); err != nil {
		decodedKey.Wipe()
		log.Printf("error decoding recovery code: %v", err)
		return nil, ErrRecoveryCode
	}
	return decodedKey.resize(metadata.PolicyKeyLen)
}

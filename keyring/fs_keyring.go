/*
 * fs_keyring.go - Add/remove encryption policy keys to/from filesystem
 *
 * Copyright 2019 Google LLC
 * Author: Eric Biggers (ebiggers@google.com)
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

package keyring

/*
#include <string.h>
*/
import "C"

import (
	"encoding/hex"
	"log"
	"os"
	"os/user"
	"sync"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/filesystem"
)

var (
	fsKeyringSupported      bool
	fsKeyringSupportedKnown bool
	fsKeyringSupportedLock  sync.Mutex
)

func checkForFsKeyringSupport(mount *filesystem.Mount) bool {
	dir, err := os.Open(mount.Path)
	if err != nil {
		log.Printf("Unexpected error opening %q. Assuming filesystem keyring is unsupported.",
			mount.Path)
		return false
	}
	defer dir.Close()

	// FS_IOC_ADD_ENCRYPTION_KEY with a NULL argument will fail with ENOTTY
	// if the ioctl isn't supported.  Otherwise it should fail with EFAULT.
	//
	// Note that there's no need to check for FS_IOC_REMOVE_ENCRYPTION_KEY
	// support separately, since it's guaranteed to be available if
	// FS_IOC_ADD_ENCRYPTION_KEY is.  There's also no need to check for
	// support on every filesystem separately, since either the kernel
	// supports the ioctls on all fscrypt-capable filesystems or it doesn't.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, dir.Fd(), unix.FS_IOC_ADD_ENCRYPTION_KEY, 0)
	if errno == unix.ENOTTY {
		log.Printf("Kernel doesn't support filesystem keyring. Falling back to user keyring.")
		return false
	}
	if errno == unix.EFAULT {
		log.Printf("Detected support for filesystem keyring")
	} else {
		// EFAULT is expected, but as long as we didn't get ENOTTY the
		// ioctl should be available.
		log.Printf("Unexpected error from FS_IOC_ADD_ENCRYPTION_KEY(%q, NULL): %v", mount.Path, errno)
	}
	return true
}

// isFsKeyringSupported returns true if the kernel supports the ioctls to
// add/remove fscrypt keys directly to/from the filesystem.  For support to be
// detected, the given Mount must be for a filesystem that supports fscrypt.
func isFsKeyringSupported(mount *filesystem.Mount) bool {
	fsKeyringSupportedLock.Lock()
	defer fsKeyringSupportedLock.Unlock()
	if !fsKeyringSupportedKnown {
		fsKeyringSupported = checkForFsKeyringSupport(mount)
		fsKeyringSupportedKnown = true
	}
	return fsKeyringSupported
}

// buildKeySpecifier converts the key descriptor string to an FscryptKeySpecifier.
func buildKeySpecifier(spec *unix.FscryptKeySpecifier, descriptor string) error {
	descriptorBytes, err := hex.DecodeString(descriptor)
	if err != nil {
		return errors.Errorf("key descriptor %q is invalid", descriptor)
	}
	switch len(descriptorBytes) {
	case unix.FSCRYPT_KEY_DESCRIPTOR_SIZE:
		spec.Type = unix.FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR
	default:
		return errors.Errorf("key descriptor %q has unknown length", descriptor)
	}
	copy(spec.U[:], descriptorBytes)
	return nil
}

// fsAddEncryptionKey adds the specified encryption key to the specified filesystem.
func fsAddEncryptionKey(key *crypto.Key, descriptor string,
	mount *filesystem.Mount, user *user.User) error {

	dir, err := os.Open(mount.Path)
	if err != nil {
		return err
	}
	defer dir.Close()

	argKey, err := crypto.NewBlankKey(int(unsafe.Sizeof(unix.FscryptAddKeyArg{})) + key.Len())
	if err != nil {
		return err
	}
	defer argKey.Wipe()
	arg := (*unix.FscryptAddKeyArg)(argKey.UnsafePtr())

	if err = buildKeySpecifier(&arg.Key_spec, descriptor); err != nil {
		return err
	}

	raw := unsafe.Pointer(uintptr(argKey.UnsafePtr()) + unsafe.Sizeof(*arg))
	arg.Raw_size = uint32(key.Len())
	C.memcpy(raw, key.UnsafePtr(), C.size_t(key.Len()))

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, dir.Fd(),
		unix.FS_IOC_ADD_ENCRYPTION_KEY, uintptr(argKey.UnsafePtr()))
	log.Printf("FS_IOC_ADD_ENCRYPTION_KEY(%q, %s, <raw>) = %v", mount.Path, descriptor, errno)
	if errno != 0 {
		return errors.Wrap(ErrKeyAdd, errno.Error())
	}
	return nil
}

// fsRemoveEncryptionKey removes the specified encryption key from the specified
// filesystem.
func fsRemoveEncryptionKey(descriptor string, mount *filesystem.Mount,
	user *user.User) error {

	dir, err := os.Open(mount.Path)
	if err != nil {
		return err
	}
	defer dir.Close()

	var arg unix.FscryptRemoveKeyArg
	if err = buildKeySpecifier(&arg.Key_spec, descriptor); err != nil {
		return err
	}

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, dir.Fd(),
		unix.FS_IOC_REMOVE_ENCRYPTION_KEY, uintptr(unsafe.Pointer(&arg)))
	log.Printf("FS_IOC_REMOVE_ENCRYPTION_KEY(%q, %s) = %v, removal_status_flags=0x%x",
		mount.Path, descriptor, errno, arg.Removal_status_flags)
	switch errno {
	case 0:
		if arg.Removal_status_flags&unix.FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY != 0 {
			return ErrKeyFilesOpen
		}
		return nil
	case unix.ENOKEY:
		return ErrKeyNotPresent
	default:
		return errors.Wrap(ErrKeyRemove, errno.Error())
	}
}

// fsGetEncryptionKeyStatus gets the status of the specified encryption key on
// the specified filesystem.
func fsGetEncryptionKeyStatus(descriptor string, mount *filesystem.Mount,
	user *user.User) (KeyStatus, error) {

	dir, err := os.Open(mount.Path)
	if err != nil {
		return KeyStatusUnknown, err
	}
	defer dir.Close()

	var arg unix.FscryptGetKeyStatusArg
	err = buildKeySpecifier(&arg.Key_spec, descriptor)
	if err != nil {
		return KeyStatusUnknown, err
	}

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, dir.Fd(),
		unix.FS_IOC_GET_ENCRYPTION_KEY_STATUS, uintptr(unsafe.Pointer(&arg)))
	log.Printf("FS_IOC_GET_ENCRYPTION_KEY_STATUS(%q, %s) = %v, status=%d, status_flags=0x%x",
		mount.Path, descriptor, errno, arg.Status, arg.Status_flags)
	if errno != 0 {
		return KeyStatusUnknown, errors.Wrap(ErrKeySearch, errno.Error())
	}
	switch arg.Status {
	case unix.FSCRYPT_KEY_STATUS_ABSENT:
		return KeyAbsent, nil
	case unix.FSCRYPT_KEY_STATUS_PRESENT:
		return KeyPresent, nil
	case unix.FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED:
		return KeyAbsentButFilesBusy, nil
	default:
		return KeyStatusUnknown,
			errors.Wrapf(ErrKeySearch, "unknown key status (%d)", arg.Status)
	}
}

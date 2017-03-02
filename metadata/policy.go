/*
 * policy.go - Functions for getting and setting policies on a specified
 * directory or file.
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

package metadata

import (
	"encoding/hex"
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"fscrypt/util"
)

// DescriptorLen is the length of all Protector and Policy descriptors.
const DescriptorLen = 2 * unix.FS_KEY_DESCRIPTOR_SIZE

// Encryption specific errors
var (
	ErrEncryptionNotSupported = errors.New("filesystem encryption is not supported")
	ErrEncryptionDisabled     = errors.New("filesystem encryption has been disabled in the kernel config")
	ErrNotEncrypted           = errors.New("file or directory not encrypted")
	ErrEncrypted              = errors.New("file or directory already encrypted")
	ErrBadEncryptionOptions   = errors.New("invalid encryption options provided")
)

// policyIoctl is a wrapper for the ioctl syscall. If opens the file at the path
// and passes the correct pointers and file descriptors to the IOCTL syscall.
// This function also takes some of the unclear errors returned by the syscall
// and translates then into more specific error strings.
func policyIoctl(path string, request uintptr, policy *unix.FscryptPolicy) error {
	file, err := os.Open(path)
	if err != nil {
		// For PathErrors, we just want the underlying error
		return util.UnderlyingError(err)
	}
	defer file.Close()

	// The returned errno value can sometimes give strange errors, so we
	// return encryption specific errors.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), request, uintptr(unsafe.Pointer(policy)))
	switch errno {
	case 0:
		return nil
	case unix.ENOTTY:
		return ErrEncryptionNotSupported
	case unix.EOPNOTSUPP:
		return ErrEncryptionDisabled
	case unix.ENODATA, unix.ENOENT:
		// ENOENT was returned instead of ENODATA on some filesystems before v4.11.
		return ErrNotEncrypted
	case unix.EEXIST:
		// EINVAL was returned instead of EEXIST on some filesystems before v4.11.
		return ErrEncrypted
	default:
		return errno
	}
}

// DefaultOptions use the only supported encryption modes and maximum padding.
var DefaultOptions = &EncryptionOptions{
	Padding:       32,
	ContentsMode:  EncryptionMode_XTS,
	FilenamesMode: EncryptionMode_CTS,
}

// Maps EncryptionOptions.Padding <-> FscryptPolicy.Flags
var (
	paddingArray = []int64{4, 8, 16, 32}
	flagsArray   = []int64{unix.FS_POLICY_FLAGS_PAD_4, unix.FS_POLICY_FLAGS_PAD_8,
		unix.FS_POLICY_FLAGS_PAD_16, unix.FS_POLICY_FLAGS_PAD_32}
)

// GetPolicy returns the Policy data for the given directory or file (includes
// the KeyDescriptor and the encryption options). Returns an error if the
// path is not encrypted or the policy couldn't be retrieved.
func GetPolicy(path string) (*PolicyData, error) {
	var policy unix.FscryptPolicy
	if err := policyIoctl(path, unix.FS_IOC_GET_ENCRYPTION_POLICY, &policy); err != nil {
		return nil, err
	}

	// Convert the padding flag into an amount of padding
	paddingFlag := int64(policy.Flags & unix.FS_POLICY_FLAGS_PAD_MASK)
	padding, ok := util.Lookup(paddingFlag, flagsArray, paddingArray)
	if !ok {
		return nil, util.SystemErrorF("invalid padding flag: %x", paddingFlag)
	}

	return &PolicyData{
		KeyDescriptor: hex.EncodeToString(policy.Master_key_descriptor[:]),
		Options: &EncryptionOptions{
			Padding:       padding,
			ContentsMode:  EncryptionMode(policy.Contents_encryption_mode),
			FilenamesMode: EncryptionMode(policy.Filenames_encryption_mode),
		},
	}, nil
}

// SetPolicy sets up the specified directory to be encrypted with the specified
// policy. Returns an error if we cannot set the policy for any reason (not a
// directory, invalid options or KeyDescriptor, etc).
func SetPolicy(path string, data *PolicyData) error {
	// Convert the padding value to a flag
	paddingFlag, ok := util.Lookup(data.Options.Padding, paddingArray, flagsArray)
	if !ok {
		return util.InvalidInputF("padding of %d", data.Options.Padding)
	}

	// Convert the policyDescriptor to a byte array
	if len(data.KeyDescriptor) != DescriptorLen {
		return util.InvalidLengthError("policy descriptor", DescriptorLen, len(data.KeyDescriptor))
	}

	descriptorBytes, err := hex.DecodeString(data.KeyDescriptor)
	if err != nil {
		return util.InvalidInputF("policy descriptor of %s: %v", data.KeyDescriptor, err)
	}

	policy := unix.FscryptPolicy{
		Version:                   0, // Version must always be zero
		Contents_encryption_mode:  uint8(data.Options.ContentsMode),
		Filenames_encryption_mode: uint8(data.Options.FilenamesMode),
		Flags: uint8(paddingFlag),
	}
	copy(policy.Master_key_descriptor[:], descriptorBytes)

	if err = policyIoctl(path, unix.FS_IOC_SET_ENCRYPTION_POLICY, &policy); err != nil {
		// Before kernel v4.11, many different errors all caused unix.EINVAL to be returned.
		// We try to disambiguate this error here. This disambiguation will not always give
		// the correct error due to a potential race condition on path.
		if err == unix.EINVAL {
			// Checking if the path is not a directory
			if info, err := os.Stat(path); err != nil || !info.IsDir() {
				return unix.ENOTDIR
			}
			// Checking if a policy is already set on this directory
			if _, err := GetPolicy(path); err == nil {
				return ErrEncrypted
			}
			// Could not get a more detailed error, return generic "bad options".
			return ErrBadEncryptionOptions
		}
		return err
	}

	return nil
}

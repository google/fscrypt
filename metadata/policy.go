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
	"log"
	"math"
	"os"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/util"
)

// Encryption specific errors
var (
	ErrEncryptionNotSupported = errors.New("encryption not supported")
	ErrEncryptionNotEnabled   = errors.New("encryption not enabled")
	ErrNotEncrypted           = errors.New("file or directory not encrypted")
	ErrEncrypted              = errors.New("file or directory already encrypted")
	ErrBadEncryptionOptions   = util.SystemError("invalid encryption options provided")
)

// policyIoctl is a wrapper around the ioctls that get and set encryption
// policies: FS_IOC_GET_ENCRYPTION_POLICY, FS_IOC_GET_ENCRYPTION_POLICY_EX, and
// FS_IOC_SET_ENCRYPTION_POLICY.  It translates the raw errno values into more
// descriptive errors.
func policyIoctl(file *os.File, request uintptr, arg unsafe.Pointer) error {
	// The returned errno value can sometimes give strange errors, so we
	// return encryption specific errors.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), request, uintptr(arg))
	switch errno {
	case 0:
		return nil
	case unix.ENOTTY:
		return ErrEncryptionNotSupported
	case unix.EOPNOTSUPP:
		return ErrEncryptionNotEnabled
	case unix.ENODATA, unix.ENOENT:
		// ENOENT was returned instead of ENODATA on some filesystems before v4.11.
		return ErrNotEncrypted
	case unix.EEXIST:
		return ErrEncrypted
	default:
		return errno
	}
}

// Maps EncryptionOptions.Padding <-> FSCRYPT_POLICY_FLAGS
var (
	paddingArray = []int64{4, 8, 16, 32}
	flagsArray   = []int64{unix.FSCRYPT_POLICY_FLAGS_PAD_4, unix.FSCRYPT_POLICY_FLAGS_PAD_8,
		unix.FSCRYPT_POLICY_FLAGS_PAD_16, unix.FSCRYPT_POLICY_FLAGS_PAD_32}
)

// flagsToPadding returns the amount of padding specified in the policy flags.
func flagsToPadding(flags uint8) int64 {
	paddingFlag := int64(flags & unix.FS_POLICY_FLAGS_PAD_MASK)

	// This lookup should always succeed
	padding, ok := util.Lookup(paddingFlag, flagsArray, paddingArray)
	if !ok {
		log.Panicf("padding flag of %x not found", paddingFlag)
	}
	return padding
}

func buildV1PolicyData(policy *unix.FscryptPolicyV1) *PolicyData {
	return &PolicyData{
		KeyDescriptor: hex.EncodeToString(policy.Master_key_descriptor[:]),
		Options: &EncryptionOptions{
			Padding:       flagsToPadding(policy.Flags),
			Contents:      EncryptionOptions_Mode(policy.Contents_encryption_mode),
			Filenames:     EncryptionOptions_Mode(policy.Filenames_encryption_mode),
			PolicyVersion: 1,
		},
	}
}

func buildV2PolicyData(policy *unix.FscryptPolicyV2) *PolicyData {
	return &PolicyData{
		KeyDescriptor: hex.EncodeToString(policy.Master_key_identifier[:]),
		Options: &EncryptionOptions{
			Padding:       flagsToPadding(policy.Flags),
			Contents:      EncryptionOptions_Mode(policy.Contents_encryption_mode),
			Filenames:     EncryptionOptions_Mode(policy.Filenames_encryption_mode),
			PolicyVersion: 2,
		},
	}
}

// GetPolicy returns the Policy data for the given directory or file (includes
// the KeyDescriptor and the encryption options). Returns an error if the
// path is not encrypted or the policy couldn't be retrieved.
func GetPolicy(path string) (*PolicyData, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// First try the new version of the ioctl. This works for both v1 and v2 policies.
	var arg unix.FscryptGetPolicyExArg
	arg.Size = uint64(unsafe.Sizeof(arg.Policy))
	policyPtr := util.Ptr(arg.Policy[:])
	err = policyIoctl(file, unix.FS_IOC_GET_ENCRYPTION_POLICY_EX, unsafe.Pointer(&arg))
	if err == ErrEncryptionNotSupported {
		// Fall back to the old version of the ioctl. This works for v1 policies only.
		err = policyIoctl(file, unix.FS_IOC_GET_ENCRYPTION_POLICY, policyPtr)
		arg.Size = uint64(unsafe.Sizeof(unix.FscryptPolicyV1{}))
	}
	if err != nil {
		return nil, errors.Wrapf(err, "get encryption policy %s", path)
	}
	switch arg.Policy[0] { // arg.policy.version
	case unix.FSCRYPT_POLICY_V1:
		if arg.Size != uint64(unsafe.Sizeof(unix.FscryptPolicyV1{})) {
			// should never happen
			return nil, errors.New("unexpected size for v1 policy")
		}
		return buildV1PolicyData((*unix.FscryptPolicyV1)(policyPtr)), nil
	case unix.FSCRYPT_POLICY_V2:
		if arg.Size != uint64(unsafe.Sizeof(unix.FscryptPolicyV2{})) {
			// should never happen
			return nil, errors.New("unexpected size for v2 policy")
		}
		return buildV2PolicyData((*unix.FscryptPolicyV2)(policyPtr)), nil
	default:
		return nil, errors.Errorf("unsupported encryption policy version [%d]",
			arg.Policy[0])
	}
}

// For improved performance, use the DIRECT_KEY flag when using ciphers that
// support it, e.g. Adiantum.  It is safe because fscrypt won't reuse the key
// for any other policy.  (Multiple directories with same policy are okay.)
func shouldUseDirectKeyFlag(options *EncryptionOptions) bool {
	// Contents and filenames encryption modes must be the same
	if options.Contents != options.Filenames {
		return false
	}
	// Whitelist the modes that take a 24+ byte IV (enough room for the per-file nonce)
	return options.Contents == EncryptionOptions_Adiantum
}

func buildPolicyFlags(options *EncryptionOptions) uint8 {
	// This lookup should always succeed (as policy is valid)
	flags, ok := util.Lookup(options.Padding, paddingArray, flagsArray)
	if !ok {
		log.Panicf("padding of %d was not found", options.Padding)
	}
	if shouldUseDirectKeyFlag(options) {
		flags |= unix.FSCRYPT_POLICY_FLAG_DIRECT_KEY
	}
	return uint8(flags)
}

func setV1Policy(file *os.File, options *EncryptionOptions, descriptorBytes []byte) error {
	policy := unix.FscryptPolicyV1{
		Version:                   unix.FSCRYPT_POLICY_V1,
		Contents_encryption_mode:  uint8(options.Contents),
		Filenames_encryption_mode: uint8(options.Filenames),
		Flags:                     uint8(buildPolicyFlags(options)),
	}

	// The descriptor should always be the correct length (as policy is valid)
	if len(descriptorBytes) != unix.FSCRYPT_KEY_DESCRIPTOR_SIZE {
		log.Panic("wrong descriptor size for v1 policy")
	}
	copy(policy.Master_key_descriptor[:], descriptorBytes)

	return policyIoctl(file, unix.FS_IOC_SET_ENCRYPTION_POLICY, unsafe.Pointer(&policy))
}

func setV2Policy(file *os.File, options *EncryptionOptions, descriptorBytes []byte) error {
	policy := unix.FscryptPolicyV2{
		Version:                   unix.FSCRYPT_POLICY_V2,
		Contents_encryption_mode:  uint8(options.Contents),
		Filenames_encryption_mode: uint8(options.Filenames),
		Flags:                     uint8(buildPolicyFlags(options)),
	}

	// The descriptor should always be the correct length (as policy is valid)
	if len(descriptorBytes) != unix.FSCRYPT_KEY_IDENTIFIER_SIZE {
		log.Panic("wrong descriptor size for v2 policy")
	}
	copy(policy.Master_key_identifier[:], descriptorBytes)

	return policyIoctl(file, unix.FS_IOC_SET_ENCRYPTION_POLICY, unsafe.Pointer(&policy))
}

// SetPolicy sets up the specified directory to be encrypted with the specified
// policy. Returns an error if we cannot set the policy for any reason (not a
// directory, invalid options or KeyDescriptor, etc).
func SetPolicy(path string, data *PolicyData) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if err = data.CheckValidity(); err != nil {
		return errors.Wrap(err, "invalid policy")
	}

	descriptorBytes, err := hex.DecodeString(data.KeyDescriptor)
	if err != nil {
		return errors.New("invalid key descriptor: " + data.KeyDescriptor)
	}

	switch data.Options.PolicyVersion {
	case 1:
		err = setV1Policy(file, data.Options, descriptorBytes)
	case 2:
		err = setV2Policy(file, data.Options, descriptorBytes)
	default:
		err = errors.Errorf("policy version of %d is invalid", data.Options.PolicyVersion)
	}

	if err == unix.EINVAL {
		// Before kernel v4.11, many different errors all caused unix.EINVAL to be returned.
		// We try to disambiguate this error here. This disambiguation will not always give
		// the correct error due to a potential race condition on path.
		if info, statErr := os.Stat(path); statErr != nil || !info.IsDir() {
			// Checking if the path is not a directory
			err = unix.ENOTDIR
		} else if _, policyErr := GetPolicy(path); policyErr == nil {
			// Checking if a policy is already set on this directory
			err = ErrEncrypted
		} else {
			// Default to generic "bad options".
			err = ErrBadEncryptionOptions
		}
	}

	return errors.Wrapf(err, "set encryption policy %s", path)
}

// CheckSupport returns an error if the filesystem containing path does not
// support filesystem encryption. This can be for many reasons including an
// incompatible kernel or filesystem or not enabling the right feature flags.
func CheckSupport(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// On supported directories, giving a bad policy will return EINVAL
	badPolicy := unix.FscryptPolicyV1{
		Version:                   math.MaxUint8,
		Contents_encryption_mode:  math.MaxUint8,
		Filenames_encryption_mode: math.MaxUint8,
		Flags:                     math.MaxUint8,
	}

	err = policyIoctl(file, unix.FS_IOC_SET_ENCRYPTION_POLICY, unsafe.Pointer(&badPolicy))
	switch err {
	case nil:
		log.Panicf(`FS_IOC_SET_ENCRYPTION_POLICY succeeded when it should have failed.
			Please open an issue, filesystem %q may be corrupted.`, path)
	case unix.EINVAL, unix.EACCES:
		return nil
	}
	return err
}

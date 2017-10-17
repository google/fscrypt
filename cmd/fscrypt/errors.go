/*
 * errors.go - File which contains common error handling code for fscrypt
 * commands. This includes handling for bad usage, invalid commands, and errors
 * from the other packages
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

	"github.com/pkg/errors"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/security"
	"github.com/google/fscrypt/util"
)

// failureExitCode is the value fscrypt will return on failure.
const failureExitCode = 1

// Various errors used for the top level user interface
var (
	ErrMaxPassphrase      = util.SystemError("max passphrase length exceeded")
	ErrInvalidSource      = errors.New("invalid source type")
	ErrPassphraseMismatch = errors.New("entered passphrases do not match")
	ErrSpecifyProtector   = errors.New("multiple protectors available")
	ErrWrongKey           = errors.New("incorrect key provided")
	ErrSpecifyKeyFile     = errors.New("no key file specified")
	ErrKeyFileLength      = errors.Errorf("key file must be %d bytes", metadata.InternalKeyLen)
	ErrAllLoadsFailed     = errors.New("could not load any protectors")
	ErrPolicyUnlocked     = errors.New("this file or directory is already unlocked")
	ErrBadOwners          = errors.New("you do not own this directory")
	ErrNotEmptyDir        = errors.New("not an empty directory")
	ErrNotPassphrase      = errors.New("protector does not use a passphrase")
	ErrUnknownUser        = errors.New("unknown user")
	ErrDropCachesPerm     = errors.New("inode cache can only be dropped as root")
	ErrSpecifyUser        = errors.New("user must be specified when run as root")
)

var loadHelpText = fmt.Sprintf("You may need to mount a linked filesystem. Run with %s for more information.", shortDisplay(verboseFlag))

var fscryptHelpTextMap = map[error]string{
	actions.ErrBadConfigFile: `Run "sudo fscrypt setup" to recreate the file.`,
}

// getErrorSuggestions returns a string containing suggestions about how to fix
// an error. If no suggestion is necessary or available, return empty string.
func getErrorSuggestions(err error) string {
	switch errors.Cause(err) {
	case filesystem.ErrNotSetup:
		return fmt.Sprintf(`Run "fscrypt setup %s" to use fscrypt on this filesystem.`, mountpointArg)
	case crypto.ErrKeyLock:
		return `Too much memory was requested to be locked in RAM. The
			current limit for this user can be checked with "ulimit
			-l". The limit can be modified by either changing the
			"memlock" item in /etc/security/limits.conf or by
			changing the "LimitMEMLOCK" value in systemd.`
	case metadata.ErrEncryptionNotSupported:
		return `Encryption for this type of filesystem is not supported
			on this kernel version.`
	case metadata.ErrEncryptionNotEnabled:
		return `Encryption is either disabled in the kernel config, or
			needs to be enabled for this filesystem. See the
			documentation on how to enable encryption on ext4
			systems (and the risks of doing so).`
	case security.ErrSessionUserKeying:
		return `This is usually the result of a bad PAM configuration.
			Either correct the problem in your PAM stack, enable
			pam_keyinit.so, or run "keyctl link @u @s".`
	case security.ErrAccessUserKeyring:
		return fmt.Sprintf(`You can only use %s to access the user
			keyring of another user if you are running as root.`,
			shortDisplay(userFlag))
	case actions.ErrNoConfigFile:
		return `Run "sudo fscrypt setup" to create the file.`
	case actions.ErrMissingPolicyMetadata:
		return `This file or directory has either been encrypted with
			another tool (such as e4crypt) or the corresponding
			filesystem metadata has been deleted.`
	case actions.ErrPolicyMetadataMismatch:
		return `The metadata for this encrypted directory is in an
			inconsistent state. This most likely means the filesystem
			metadata is corrupted.`
	case actions.ErrMissingProtectorName:
		return fmt.Sprintf("Use %s to specify a protector name.", shortDisplay(nameFlag))
	case ErrNoDesctructiveOps:
		return fmt.Sprintf("Use %s to automatically run destructive operations.", shortDisplay(forceFlag))
	case ErrSpecifyProtector:
		return fmt.Sprintf("Use %s to specify a protector.", shortDisplay(protectorFlag))
	case ErrSpecifyKeyFile:
		return fmt.Sprintf("Use %s to specify a key file.", shortDisplay(keyFileFlag))
	case ErrBadOwners:
		return `Encryption can only be setup on directories you own,
			even if you have write permission for the directory.`
	case ErrNotEmptyDir:
		return `Encryption can only be setup on empty directories; files
			cannot be encrypted in-place. Instead, encrypt an empty
			directory, copy the files into that encrypted directory,
			and securely delete the originals with "shred".`
	case ErrDropCachesPerm:
		return fmt.Sprintf(`Either this command should be run as root to
			properly clear the inode cache, or it should be run with
			%s=false (this may leave encrypted files and directories
			in an accessible state).`, shortDisplay(dropCachesFlag))
	case ErrSpecifyUser:
		return fmt.Sprintf(`When running this command as root, you
			usually still want to provision/remove keys for a normal
			user's keyring and use a normal user's login passphrase
			as a protector (so the corresponding files will be
			accessible for that user). This can be done with %s. To
			use the root user's keyring or passphrase, use
			--%s=root.`, shortDisplay(userFlag), userFlag.GetName())
	case ErrAllLoadsFailed:
		return loadHelpText
	default:
		return ""
	}
}

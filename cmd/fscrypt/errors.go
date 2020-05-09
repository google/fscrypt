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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/keyring"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/util"
)

// failureExitCode is the value fscrypt will return on failure.
const failureExitCode = 1

// Various errors used for the top level user interface
var (
	ErrCanceled           = errors.New("operation canceled")
	ErrNoDestructiveOps   = errors.New("operation would be destructive")
	ErrMaxPassphrase      = util.SystemError("max passphrase length exceeded")
	ErrInvalidSource      = errors.New("invalid source type")
	ErrPassphraseMismatch = errors.New("entered passphrases do not match")
	ErrSpecifyProtector   = errors.New("multiple protectors available")
	ErrWrongKey           = errors.New("incorrect key provided")
	ErrSpecifyKeyFile     = errors.New("no key file specified")
	ErrKeyFileLength      = errors.Errorf("key file must be %d bytes", metadata.InternalKeyLen)
	ErrAllLoadsFailed     = errors.New("could not load any protectors")
	ErrMustBeRoot         = errors.New("this command must be run as root")
	ErrPolicyUnlocked     = errors.New("this file or directory is already unlocked")
	ErrPolicyLocked       = errors.New("this file or directory is already locked")
	ErrBadOwners          = errors.New("you do not own this directory")
	ErrNotEmptyDir        = errors.New("not an empty directory")
	ErrNotPassphrase      = errors.New("protector does not use a passphrase")
	ErrUnknownUser        = errors.New("unknown user")
	ErrDropCachesPerm     = errors.New("inode cache can only be dropped as root")
	ErrSpecifyUser        = errors.New("user must be specified when run as root")
	ErrFsKeyringPerm      = errors.New("root is required to add/remove v1 encryption policy keys to/from filesystem")
)

var loadHelpText = fmt.Sprintf("You may need to mount a linked filesystem. Run with %s for more information.", shortDisplay(verboseFlag))

// getFullName returns the full name of the application or command being used.
func getFullName(c *cli.Context) string {
	if c.Command.HelpName != "" {
		return c.Command.HelpName
	}
	return c.App.HelpName
}

// getErrorSuggestions returns a string containing suggestions about how to fix
// an error. If no suggestion is necessary or available, return empty string.
func getErrorSuggestions(err error) string {
	switch err.(type) {
	case *actions.ErrBadConfigFile:
		return `Either fix this file manually, or run "sudo fscrypt setup" to recreate it.`
	case *actions.ErrLoginProtectorName:
		return fmt.Sprintf("To fix this, don't specify the %s option.", shortDisplay(nameFlag))
	case *actions.ErrMissingProtectorName:
		return fmt.Sprintf("Use %s to specify a protector name.", shortDisplay(nameFlag))
	case *actions.ErrNoConfigFile:
		return `Run "sudo fscrypt setup" to create this file.`
	}
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
	case keyring.ErrKeyFilesOpen:
		return `Directory was incompletely locked because some files are
			still open. These files remain accessible. Try killing
			any processes using files in the directory, then
			re-running 'fscrypt lock'.`
	case keyring.ErrKeyAddedByOtherUsers:
		return `Directory couldn't be fully locked because other user(s)
			have unlocked it. If you want to force the directory to
			be locked, use 'sudo fscrypt lock --all-users DIR'.`
	case keyring.ErrSessionUserKeying:
		return `This is usually the result of a bad PAM configuration.
			Either correct the problem in your PAM stack, enable
			pam_keyinit.so, or run "keyctl link @u @s".`
	case keyring.ErrAccessUserKeyring:
		return fmt.Sprintf(`You can only use %s to access the user
			keyring of another user if you are running as root.`,
			shortDisplay(userFlag))
	case keyring.ErrV2PoliciesUnsupported:
		return fmt.Sprintf(`v2 encryption policies are only supported by kernel
		version 5.4 and later. Either use a newer kernel, or change
		policy_version to 1 in %s.`, actions.ConfigFileLocation)
	case ErrNoDestructiveOps:
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
	case ErrFsKeyringPerm:
		return `Either this command should be run as root, or you should
			set '"use_fs_keyring_for_v1_policies": false' in
			/etc/fscrypt.conf, or you should re-create your
			encrypted directories using v2 encryption policies
			rather than v1 (this requires setting '"policy_version":
			"2"' in the "options" section of /etc/fscrypt.conf).`
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

// newExitError creates a new error for a given context and normal error. The
// returned error prepends an error tag and the name of the relevant command,
// and it will make fscrypt return a non-zero exit value.
func newExitError(c *cli.Context, err error) error {
	// Prepend the error tag and full name, and append suggestions (if any)
	prefix := "[ERROR] " + getFullName(c) + ": "
	message := prefix + wrapText(err.Error(), utf8.RuneCountInString(prefix))

	if suggestion := getErrorSuggestions(err); suggestion != "" {
		message += "\n\n" + wrapText(suggestion, 0)
	}

	return cli.NewExitError(message, failureExitCode)
}

// usageError implements cli.ExitCoder to print the usage and return a non-zero
// value. This error should be used when a command is used incorrectly.
type usageError struct {
	c       *cli.Context
	message string
}

func (u *usageError) Error() string {
	return fmt.Sprintf("%s: %s", getFullName(u.c), u.message)
}

// We get the help to print after the error by having it run right before the
// application exits. This is very nasty, but there isn't a better way to do it
// with the constraints of urfave/cli.
func (u *usageError) ExitCode() int {
	// Redirect help output to a buffer, so we can customize it.
	buf := new(bytes.Buffer)
	oldWriter := u.c.App.Writer
	u.c.App.Writer = buf

	// Get the appropriate help
	if getFullName(u.c) == filepath.Base(os.Args[0]) {
		cli.ShowAppHelp(u.c)
	} else {
		cli.ShowCommandHelp(u.c, u.c.Command.Name)
	}

	// Remove first line from help and print it out
	buf.ReadBytes('\n')
	buf.WriteTo(oldWriter)
	u.c.App.Writer = oldWriter
	return failureExitCode
}

// expectedArgsErr creates a usage error for the incorrect number of arguments
// being specified. atMost should be true only if any number of arguments from 0
// to expectedArgs would be acceptable.
func expectedArgsErr(c *cli.Context, expectedArgs int, atMost bool) error {
	message := "expected "
	if atMost {
		message += "at most "
	}
	message += fmt.Sprintf("%s, got %s",
		pluralize(expectedArgs, "argument"), pluralize(c.NArg(), "argument"))
	return &usageError{c, message}
}

// onUsageError is a function handler for the application and each command.
func onUsageError(c *cli.Context, err error, _ bool) error {
	return &usageError{c, err.Error()}
}

// checkRequiredFlags makes sure that all of the specified string flags have
// been given nonempty values. Returns a usage error on failure.
func checkRequiredFlags(c *cli.Context, flags []*stringFlag) error {
	for _, flag := range flags {
		if flag.Value == "" {
			message := fmt.Sprintf("required flag %s not provided", shortDisplay(flag))
			return &usageError{c, message}
		}
	}
	return nil
}

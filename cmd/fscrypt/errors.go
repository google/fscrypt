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
	"golang.org/x/sys/unix"

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
	ErrInvalidSource      = errors.New("invalid source type")
	ErrPassphraseMismatch = errors.New("entered passphrases do not match")
	ErrSpecifyProtector   = errors.New("multiple protectors available")
	ErrWrongKey           = errors.New("incorrect key provided")
	ErrSpecifyKeyFile     = errors.New("no key file specified")
	ErrKeyFileLength      = errors.Errorf("key file must be %d bytes", metadata.InternalKeyLen)
	ErrAllLoadsFailed     = errors.New("could not load any protectors")
	ErrMustBeRoot         = errors.New("this command must be run as root")
	ErrDirAlreadyUnlocked = errors.New("this file or directory is already unlocked")
	ErrDirAlreadyLocked   = errors.New("this file or directory is already locked")
	ErrNotPassphrase      = errors.New("protector does not use a passphrase")
	ErrUnknownUser        = errors.New("unknown user")
	ErrDropCachesPerm     = errors.New("inode cache can only be dropped as root")
	ErrSpecifyUser        = errors.New("user must be specified when run as root")
	ErrFsKeyringPerm      = errors.New("root is required to add/remove v1 encryption policy keys to/from filesystem")
)

// ErrDirFilesOpen indicates that a directory can't be fully locked because
// files protected by the directory's policy are still open.
type ErrDirFilesOpen struct {
	DirPath string
}

func (err *ErrDirFilesOpen) Error() string {
	return `Directory was incompletely locked because some files are still
	open. These files remain accessible.`
}

// ErrDirUnlockedByOtherUsers indicates that a directory can't be locked because
// the directory's policy is still provisioned by other users.
type ErrDirUnlockedByOtherUsers struct {
	DirPath string
}

func (err *ErrDirUnlockedByOtherUsers) Error() string {
	return fmt.Sprintf(`Directory %q couldn't be fully locked because other
	user(s) have unlocked it.`, err.DirPath)
}

// ErrDirNotEmpty indicates that a directory can't be encrypted because it's not
// empty.
type ErrDirNotEmpty struct {
	DirPath string
}

func (err *ErrDirNotEmpty) Error() string {
	return fmt.Sprintf("Directory %q cannot be encrypted because it is non-empty.", err.DirPath)
}

var loadHelpText = fmt.Sprintf("You may need to mount a linked filesystem. Run with %s for more information.", shortDisplay(verboseFlag))

// getFullName returns the full name of the application or command being used.
func getFullName(c *cli.Context) string {
	if c.Command.HelpName != "" {
		return c.Command.HelpName
	}
	return c.App.HelpName
}

func isGrubInstalledOnFilesystem(mnt *filesystem.Mount) bool {
	dir := filepath.Join(mnt.Path, "boot/grub")
	grubDirMount, _ := filesystem.FindMount(dir)
	return grubDirMount == mnt
}

func suggestEnablingEncryption(mnt *filesystem.Mount) string {
	kconfig := "CONFIG_FS_ENCRYPTION=y"
	switch mnt.FilesystemType {
	case "ext4":
		// Recommend running tune2fs -O encrypt.  But be really careful;
		// old kernels didn't support block_size != PAGE_SIZE, and old
		// GRUB didn't support encryption.
		var statfs unix.Statfs_t
		if err := unix.Statfs(mnt.Path, &statfs); err != nil {
			return ""
		}
		pagesize := os.Getpagesize()
		if int64(statfs.Bsize) != int64(pagesize) && !util.IsKernelVersionAtLeast(5, 5) {
			return fmt.Sprintf(`This filesystem uses a block size
			(%d) other than the system page size (%d). Ext4
			encryption didn't support this case until kernel v5.5.
			Do *not* enable encryption on this filesystem. Either
			upgrade your kernel to v5.5 or later, or re-create this
			filesystem using 'mkfs.ext4 -b %d -O encrypt %s'
			(WARNING: that will erase all data on it).`,
				statfs.Bsize, pagesize, pagesize, mnt.Device)
		}
		if !util.IsKernelVersionAtLeast(5, 1) {
			kconfig = "CONFIG_EXT4_ENCRYPTION=y"
		}
		s := fmt.Sprintf(`To enable encryption support on this
		filesystem, run:

		> sudo tune2fs -O encrypt %q
		`, mnt.Device)
		if isGrubInstalledOnFilesystem(mnt) {
			s += `
			WARNING: you seem to have GRUB installed on this
			filesystem. Before doing the above, make sure you are
			using GRUB v2.04 or later; otherwise your system will
			become unbootable.
			`
		}
		s += fmt.Sprintf(`
		Also ensure that your kernel has %s. See the documentation for
		more details.`, kconfig)
		return s
	case "f2fs":
		if !util.IsKernelVersionAtLeast(5, 1) {
			kconfig = "CONFIG_F2FS_FS_ENCRYPTION=y"
		}
		return fmt.Sprintf(`To enable encryption support on this
		filesystem, you'll need to run:

		> sudo fsck.f2fs -O encrypt %q

		Also ensure that your kernel has %s. See the documentation for
		more details.`, mnt.Device, kconfig)
	default:
		return `See the documentation for how to enable encryption
		support on this filesystem.`
	}
}

// getErrorSuggestions returns a string containing suggestions about how to fix
// an error. If no suggestion is necessary or available, return empty string.
func getErrorSuggestions(err error) string {
	switch e := err.(type) {
	case *ErrDirFilesOpen:
		return fmt.Sprintf(`Try killing any processes using files in the
		directory, for example using:

		> find %q -print0 | xargs -0 fuser -k

		Then re-run:

		> fscrypt lock %q`, e.DirPath, e.DirPath)
	case *ErrDirNotEmpty:
		dir := filepath.Clean(e.DirPath)
		newDir := dir + ".new"
		return fmt.Sprintf(`Files cannot be encrypted in-place. Instead,
		encrypt a new directory, copy the files into it, and securely
		delete the original directory. For example:

		> mkdir %q
		> fscrypt encrypt %q
		> cp -a -T %q %q
		> find %q -type f -print0 | xargs -0 shred -n1 --remove=unlink
		> rm -rf %q
		> mv %q %q

		Caution: due to the nature of modern storage devices and filesystems,
		the original data may still be recoverable from disk. It's much better
		to encrypt your files from the start.`, newDir, newDir, dir, newDir, dir, dir, newDir, dir)
	case *ErrDirUnlockedByOtherUsers:
		return fmt.Sprintf(`If you want to force the directory to be
		locked, use:

		> sudo fscrypt lock --all-users %q`, e.DirPath)
	case *actions.ErrBadConfigFile:
		return `Either fix this file manually, or run "sudo fscrypt setup" to recreate it.`
	case *actions.ErrLoginProtectorName:
		return fmt.Sprintf("To fix this, don't specify the %s option.", shortDisplay(nameFlag))
	case *actions.ErrMissingProtectorName:
		return fmt.Sprintf("Use %s to specify a protector name.", shortDisplay(nameFlag))
	case *actions.ErrNoConfigFile:
		return `Run "sudo fscrypt setup" to create this file.`
	case *filesystem.ErrEncryptionNotEnabled:
		return suggestEnablingEncryption(e.Mount)
	case *filesystem.ErrEncryptionNotSupported:
		switch e.Mount.FilesystemType {
		case "ext4":
			if !util.IsKernelVersionAtLeast(4, 1) {
				return "ext4 encryption requires kernel v4.1 or later."
			}
		case "f2fs":
			if !util.IsKernelVersionAtLeast(4, 2) {
				return "f2fs encryption requires kernel v4.2 or later."
			}
		case "ubifs":
			if !util.IsKernelVersionAtLeast(4, 10) {
				return "ubifs encryption requires kernel v4.10 or later."
			}
		}
		return ""
	case *filesystem.ErrNoCreatePermission:
		return `For how to allow users to create fscrypt metadata on a
			filesystem, refer to
			https://github.com/google/fscrypt#setting-up-fscrypt-on-a-filesystem`
	case *filesystem.ErrNotSetup:
		return fmt.Sprintf(`Run "sudo fscrypt setup %s" to use fscrypt
		        on this filesystem.`, e.Mount.Path)
	case *keyring.ErrAccessUserKeyring:
		return fmt.Sprintf(`You can only use %s to access the user
			keyring of another user if you are running as root.`,
			shortDisplay(userFlag))
	case *keyring.ErrSessionUserKeyring:
		return `This is usually the result of a bad PAM configuration.
			Either correct the problem in your PAM stack, enable
			pam_keyinit.so, or run "keyctl link @u @s".`
	}
	switch errors.Cause(err) {
	case crypto.ErrMlockUlimit:
		return `Too much memory was requested to be locked in RAM. The
			current limit for this user can be checked with "ulimit
			-l". The limit can be modified by either changing the
			"memlock" item in /etc/security/limits.conf or by
			changing the "LimitMEMLOCK" value in systemd.`
	case keyring.ErrV2PoliciesUnsupported:
		return fmt.Sprintf(`v2 encryption policies are only supported by kernel
		version 5.4 and later. Either use a newer kernel, or change
		policy_version to 1 in %s.`, actions.ConfigFileLocation)
	case ErrNoDestructiveOps:
		return fmt.Sprintf("If desired, use %s to automatically run destructive operations.",
			shortDisplay(forceFlag))
	case ErrSpecifyProtector:
		return fmt.Sprintf("Use %s to specify a protector.", shortDisplay(protectorFlag))
	case ErrSpecifyKeyFile:
		return fmt.Sprintf("Use %s to specify a key file.", shortDisplay(keyFileFlag))
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

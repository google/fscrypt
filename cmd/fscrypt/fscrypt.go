/*
 * fscrypt.go - File which starts up and runs the application. Initializes
 * information about the application like the name, version, author, etc...
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

/*
fscrypt is a command line tool for managing linux filesystem encryption.
*/

package main

import (
	"fmt"

	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/security"
	"github.com/pkg/errors"

	"github.com/google/fscrypt/actions"

	"github.com/google/fscrypt/cmd"
)

// Arguments used in fscrypt commands.
var (
	unusedMountpointArg = &cmd.Argument{
		Name:  "mountpoint",
		Usage: "path to a mountpoint on which to setup fscrypt",
	}
	usedMountpointArg = &cmd.Argument{
		Name:  "mountpoint",
		Usage: "path to a mountpoint being used with fscrypt",
	}
	directoryToEncryptArg = &cmd.Argument{
		Name:  "directory",
		Usage: "path to an empty directory to encrypt with fscrypt",
	}
	encryptedPathArg = &cmd.Argument{
		Name:  "path",
		Usage: "file or directory encrypted with fscrypt",
	}
)

func main() { fscryptCommand.Run() }

var fscryptCommand = cmd.Command{
	Title: "manage linux filesystem encryption",
	UsageLines: []string{
		fmt.Sprintf("<command> [arguments] [command options] [%s | %s]",
			cmd.VerboseFlag, cmd.QuietFlag),
		cmd.VersionUsage,
	},
	SubCommands: []*Command{
		setupCommand,
		encryptCommand,
		unlockCommand,
		purgeCommand,
		// statusCommand,
		// metadataCommand,
		cmd.VersionCommand,
	},
	Flags:   []cmd.Flag{cmd.VerboseFlag, cmd.QuietFlag, cmd.HelpFlag},
	ManPage: &cmd.ManPage{Name: "fscrypt", Section: 8},
}

// setup performs global or per-filesystem initialization of fscrypt data.
var setupCommand = &cmd.Command{
	Name:  "setup",
	Title: "setup a system/filesystem to use fscrypt",
	UsageLines: []string{
		fmt.Sprintf("[options]"),
		fmt.Sprintf("%s [%s]", unusedMountpointArg, cmd.ForceFlag),
	},
	Arguments:    []*cmd.Argument{unusedMountpointArg},
	InheritFlags: true,
	Flags:        []cmd.Flag{configFileFlag, targetFlag, legacyFlag, cmd.ForceFlag},
	ManPage:      &cmd.ManPage{Name: "fscrypt-setup", Section: 8},
	Action:       setupAction,
}

func setupAction(c *cmd.Context) error {
	switch len(c.Args) {
	case 0:
		// Case (1) - global setup
		return createGlobalConfig(configFileFlag.Value)
	case 1:
		// Case (2) - filesystem setup
		return setupFilesystem(c.Args[0])
	default:
		return cmd.CheckExpectedArgs(c, 1, true)
	}
}

// encrypt takes an empty directory, enables encryption, and unlocks it.
var encryptCommand = &cmd.Command{
	Name:         "encrypt",
	Title:        "start encrypting an empty directory",
	UsageLines:   nil, // TODO(joerichey)
	Arguments:    []*cmd.Argument{directoryToEncryptArg},
	InheritFlags: true,
	Flags: []cmd.Flag{sourceFlag, nameFlag, protectorFlag, policyFlag,
		keyFileFlag, userFlag, skipUnlockFlag},
	ManPage: &cmd.ManPage{Name: "fscrypt-encrypt", Section: 8},
	Action:  encryptAction,
}

func encryptAction(c *cmd.Context) error {
	if err := cmd.CheckExpectedArgs(c, 1, false); err != nil {
		return err
	}

	path := c.Args[0]
	if err := encryptPath(path); err != nil {
		return err
	}

	if !skipUnlockFlag.Value {
		fmt.Fprintf(cmd.Output, "%q is now encrypted, unlocked, and ready for use.\n", path)
		return nil
	}

	fmt.Fprintf(cmd.Output, "%q is now encrypted, but it is still locked.\n", path)
	fmt.Fprintf(cmd.Output, "It can be unlocked with: fscrypt unlock %q\n", path)
	return nil
}

// unlock takes an encrypted path and makes it available for reading/writing.
var unlockCommand = &cmd.Command{
	Name:         "unlock",
	Title:        "unlock an encrypted file or directory",
	UsageLines:   nil, // TODO(joerichey)
	Arguments:    []*cmd.Argument{encryptedPathArg},
	InheritFlags: true,
	Flags:        []cmd.Flag{protectorFlag, policyFlag, keyFileFlag, userFlag},
	ManPage:      &cmd.ManPage{Name: "fscrypt-unlock", Section: 8},
	Action:       unlockAction,
}

func unlockAction(c *cmd.Context) error {
	if err := cmd.CheckExpectedArgs(c, 1, false); err != nil {
		return err
	}

	path := c.Args[0]
	if err := unlockPath(path); err != nil {
		return err
	}

	fmt.Fprintf(cmd.Output, "%q is now unlocked and ready for use.\n", path)
	return nil
}

// purge removes all the policy keys from the keyring (my require unmount).
var purgeCommand = &cmd.Command{
	Name:  "purge",
	Title: "remove a directory's encryption keys",
	UsageLines: []string{fmt.Sprintf("%s, [%s=false] [%s] [%s]",
		usedMountpointArg, dropCachesFlag, userFlag, cmd.ForceFlag)},
	Arguments:    []*cmd.Argument{usedMountpointArg},
	InheritFlags: true,
	Flags:        []cmd.Flag{dropCachesFlag, userFlag, cmd.ForceFlag},
	ManPage:      &cmd.ManPage{Name: "fscrypt-purge", Section: 8},
	Action:       purgeAction,
}

func purgeAction(c *cmd.Context) error {
	if err := cmd.CheckExpectedArgs(c, 1, false); err != nil {
		return err
	}
	if dropCachesFlag.Value {
		if cmd.CheckIfRoot() != nil {
			return ErrDropCachesPerm
		}
	}

	targetUser, err := parseUserFlag(true)
	if err != nil {
		return err
	}
	ctx, err := actions.NewContextFromMountpoint(c.Args[0], target)
	if err != nil {
		return err
	}

	question := fmt.Sprintf("Purge all policy keys from %q", ctx.Mount.Path)
	if dropCachesFlag.Value {
		question += " and drop global inode cache"
	}
	warning := "Encrypted data on this filesystem will be inaccessible until unlocked again!!"
	if err = cmd.AskConfirmation(question+"?", warning, false); err != nil {
		return err
	}
	if err = actions.PurgeAllPolicies(ctx); err != nil {
		return err
	}
	fmt.Fprintf(cmd.Output, "Policies purged from filesystem %q.\n", ctx.Mount.Path)

	if !dropCachesFlag.Value {
		fmt.Fprintf(cmd.Output, "Filesystem %q should now be unmounted.\n", cmd.Mount.Path)
		return nil
	}
	if err = security.DropFilesystemCache(); err != nil {
		return err
	}
	fmt.Fprintln(cmd.Output, "Encrypted data removed from filesystem cache.")
	return nil
}

// status is a command that gets info about the system, a mountpoint, or a path.
var statusCommand = &cmd.Command{
	Name:       "status",
	Title:      "get the status of the system or a path",
	UsageLines: []string{"", usedMountpointArg.String(), encryptedPathArg.String()},
	Flags:      []cmd.Flag{cmd.VerboseFlag, cmd.HelpFlag},
	ManPage:    &cmd.ManPage{Name: "fscrypt-status", Section: 8},
	Action:     statusAction,
}

func statusAction(c *cmd.Context) error {
	switch len(c.Args) {
	case 0:
		// Case (1) - global status
		return writeGlobalStatus()
	case 1:
		path := c.Args[0]
		ctx, mntErr := actions.NewContextFromMountpoint(path, nil)

		switch errors.Cause(mntErr) {
		case nil:
			// Case (2) - mountpoint status
			return writeFilesystemStatus(ctx)
		case filesystem.ErrNotAMountpoint:
			// Case (3) - file or directory status
			return writePathStatus(path)
		default:
			return mntErr
		}
	default:
		return expectedArgsErr(c, 1, true)
	}
}

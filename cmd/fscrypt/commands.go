/*
 * commands.go - Implementations of all of the fscrypt commands and subcommands.
 * This mostly just calls into the fscrypt/actions package.
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
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
)

// Setup is a command which can to global or per-filesystem initialization.
var Setup = cli.Command{
	Name:      "setup",
	ArgsUsage: fmt.Sprintf("[%s]", mountpointArg),
	Usage:     "perform global setup or filesystem setup",
	Description: fmt.Sprintf(`This command creates fscrypt's global config
		file or enables fscrypt on a filesystem.

		(1) When used without %[1]s, create the parameters in %[2]s.
		This is primarily used to configure the passphrase hashing
		parameters to the appropriate hardness (as determined by %[3]s).
		Being root is required to write the config file.

		(2) When used with %[1]s, enable fscrypt on %[1]s. This involves
		creating the necessary folders on the filesystem which will hold
		the metadata structures. Begin root may be required to create
		these folders.`, mountpointArg, actions.ConfigFileLocation,
		shortDisplay(timeTargetFlag)),
	Flags:  []cli.Flag{timeTargetFlag, legacyFlag, forceFlag},
	Action: setupAction,
}

func setupAction(c *cli.Context) error {
	var err error

	switch c.NArg() {
	case 0:
		// Case (1) - global setup
		err = createGlobalConfig(c.App.Writer, actions.ConfigFileLocation)
	case 1:
		// Case (2) - filesystem setup
		err = setupFilesystem(c.App.Writer, c.Args().Get(0))
	default:
		return expectedArgsErr(c, 1, true)
	}

	if err != nil {
		return newExitError(c, err)
	}
	return nil
}

// Encrypt performs the functions of setupDirectory and Unlock in one command.
var Encrypt = cli.Command{
	Name:      "encrypt",
	ArgsUsage: directoryArg,
	Usage:     "enable filesystem encryption for a directory",
	Description: fmt.Sprintf(`This command enables filesystem encryption on
		%[1]s. This may involve creating a new policy (if one is not
		specified with %[2]s) or a new protector (if one is not
		specified with %[3]s). This command requires that the
		corresponding filesystem has been setup with "fscrypt setup
		%[4]s". By default, after %[1]s is setup, it is unlocked and can
		immediately be used.`, directoryArg, shortDisplay(policyFlag),
		shortDisplay(protectorFlag), mountpointArg),
	Flags: []cli.Flag{policyFlag, unlockWithFlag, protectorFlag, sourceFlag,
		nameFlag, keyFileFlag, skipUnlockFlag},
	Action: encryptAction,
}

func encryptAction(c *cli.Context) error {
	if c.NArg() != 1 {
		return expectedArgsErr(c, 1, false)
	}

	path := c.Args().Get(0)
	if err := encryptPath(path); err != nil {
		return newExitError(c, err)
	}

	if !skipUnlockFlag.Value {
		fmt.Fprintf(c.App.Writer,
			"%q is now encrypted, unlocked, and ready for use.\n", path)
	} else {
		fmt.Fprintf(c.App.Writer,
			"%q is now encrypted, but it is still locked.\n", path)
		fmt.Fprintln(c.App.Writer, `It can be unlocked with "fscrypt unlock".`)
	}
	return nil
}

// encryptPath sets up encryption on path and provisions the policy to the
// keyring unless --skip-unlock is used. On failure, an error is returned, any
// metadata creation is reverted, and the directory is unmodified.
func encryptPath(path string) (err error) {
	ctx, err := actions.NewContextFromPath(path)
	if err != nil {
		return
	}
	if err = checkEncryptable(ctx, path); err != nil {
		return
	}

	var policy *actions.Policy
	if policyFlag.Value != "" {
		log.Printf("getting policy for %q", path)

		policy, err = getPolicyFromFlag(policyFlag.Value)
	} else {
		log.Printf("creating policy for %q", path)

		protector, created, protErr := selectOrCreateProtector(ctx)
		// Successfully created protector should be reverted on failure.
		if protErr != nil {
			return protErr
		}
		defer func() {
			protector.Lock()
			if err != nil && created {
				protector.Revert()
			}
		}()

		if err = protector.Unlock(existingKeyFn); err != nil {
			return
		}
		policy, err = actions.CreatePolicy(ctx, protector)
	}
	// Successfully created policy should be reverted on failure.
	if err != nil {
		return
	}
	defer func() {
		policy.Lock()
		if err != nil {
			policy.Deprovision()
			policy.Revert()
		}
	}()

	// Unlock() first, so if the Unlock() fails the directory isn't changed.
	if !skipUnlockFlag.Value {
		if err = policy.Unlock(optionFn, existingKeyFn); err != nil {
			return
		}
		if err = policy.Provision(); err != nil {
			return
		}
	}
	if err = policy.Apply(path); os.IsPermission(errors.Cause(err)) {
		// EACCES at this point indicates ownership issues.
		err = errors.Wrap(ErrBadOwners, path)
	}
	return
}

// checkEncryptable returns an error if the path cannot be encrypted.
func checkEncryptable(ctx *actions.Context, path string) error {
	log.Printf("ensuring %s is an empty and readable directory", path)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	switch names, err := f.Readdirnames(-1); {
	case err != nil:
		// Could not read directory (might not be a directory)
		log.Print(errors.Wrap(err, path))
		return errors.Wrap(ErrNotEmptyDir, path)
	case len(names) > 0:
		log.Printf("directory %s is not empty", path)
		return errors.Wrap(ErrNotEmptyDir, path)
	}

	log.Printf("ensuring %s is not encrypted and filesystem is using fscrypt", path)
	switch _, err := actions.GetPolicyFromPath(ctx, path); errors.Cause(err) {
	case metadata.ErrNotEncrypted:
		// We are not encrypted
		return nil
	case nil:
		// We are encrypted
		return errors.Wrap(metadata.ErrEncrypted, path)
	default:
		return err
	}
}

// selectOrCreateProtector uses user input (or flags) to either create a new
// protector or select and existing one. The boolean return value is true if we
// created a new protector.
func selectOrCreateProtector(ctx *actions.Context) (*actions.Protector, bool, error) {
	if protectorFlag.Value != "" {
		protector, err := getProtectorFromFlag(protectorFlag.Value)
		return protector, false, err
	}

	options, err := expandedProtectorOptions(ctx)
	if err != nil {
		return nil, false, err
	}

	// Having no existing options to choose from or using creation-only
	// flags indicates we should make a new protector.
	if len(options) == 0 || nameFlag.Value != "" || sourceFlag.Value != "" {
		protector, err := createProtectorFromContext(ctx)
		return protector, true, err
	}

	shouldCreate, err := askQuestion("Should we create a new protector?", false)
	if err != nil {
		return nil, false, err
	}
	if shouldCreate {
		protector, err := createProtectorFromContext(ctx)
		return protector, true, err
	}

	log.Print("finding an existing protector to use")
	protector, err := selectExistingProtector(ctx, options)
	return protector, false, err
}

// Unlock takes an encrypted directory and unlocks it for reading and writing.
var Unlock = cli.Command{
	Name:      "unlock",
	ArgsUsage: directoryArg,
	Usage:     "unlock an encrypted directory",
	Description: fmt.Sprintf(`This command takes %s, a directory setup for
		use with fscrypt, and unlocks the directory by passing the
		appropriate key into the keyring. This requires unlocking one of
		the protectors protecting this directory (either by selecting a
		protector or specifying one with %s). This directory will be
		locked again upon reboot, or after running "fscrypt purge" and
		unmounting the corresponding filesystem.`, directoryArg,
		shortDisplay(unlockWithFlag)),
	Flags:  []cli.Flag{unlockWithFlag, keyFileFlag},
	Action: unlockAction,
}

func unlockAction(c *cli.Context) error {
	if c.NArg() != 1 {
		return expectedArgsErr(c, 1, false)
	}

	path := c.Args().Get(0)
	ctx, err := actions.NewContextFromPath(path)
	if err != nil {
		return newExitError(c, err)
	}

	log.Printf("performing sanity checks")
	// Ensure path is encrypted and filesystem is using fscrypt.
	policy, err := actions.GetPolicyFromPath(ctx, path)
	if err != nil {
		return newExitError(c, err)
	}
	// Check if directory is already unlocked
	if policy.IsProvisioned() {
		log.Printf("policy %s is already provisioned", policy)
		return newExitError(c, errors.Wrapf(ErrPolicyUnlocked, path))
	}

	if err := policy.Unlock(optionFn, existingKeyFn); err != nil {
		return newExitError(c, err)
	}
	defer policy.Lock()

	if err := policy.Provision(); err != nil {
		return newExitError(c, err)
	}

	fmt.Fprintf(c.App.Writer, "%q is now unlocked and ready for use.\n", path)
	return nil
}

// Purge removes all the policy keys from the keyring (also need unmount).
var Purge = cli.Command{
	Name:      "purge",
	ArgsUsage: mountpointArg,
	Usage:     "[EXPERIMENTAL] remove a filesystem's keys",
	Description: fmt.Sprintf(`EXPERIMENTAL: This command removes all the
		policy keys for directories on %[1]s. This is intended to lock
		all encrypted files and directories on %[1]s, in that unlocking
		them for reading will require providing a key again. However,
		this action is currently subject to two significant limitations:

		(1) If "fscrypt purge" is run, but the filesystem has not yet
		been unmounted, recently accessed encrypted directories and
		files will remain accessible for some time. Because of this,
		after purging a filesystem's keys, it is recommended to unmount
		the filesystem. This limitation might be eliminated in a future
		kernel version.

		(2) Even after unmounting the filesystem, the kernel may keep
		contents of encrypted files cached in memory. This means direct
		memory access (either though physical compromise or a kernel
		exploit) could compromise encrypted data. This weakness can be
		eliminated by cycling the power or mitigated by using page cache
		and slab cache poisoning.`, mountpointArg),
	Flags:  []cli.Flag{forceFlag},
	Action: purgeAction,
}

func purgeAction(c *cli.Context) error {
	if c.NArg() != 1 {
		return expectedArgsErr(c, 1, false)
	}

	ctx, err := actions.NewContextFromMountpoint(c.Args().Get(0))
	if err != nil {
		return newExitError(c, err)
	}

	err = askConfirmation(fmt.Sprintf(
		"Purge all policy keys from %q?",
		ctx.Mount.Path), false,
		"Encrypted data on this filesystem will be inaccessible until unlocked again!!")
	if err != nil {
		return newExitError(c, err)
	}

	if err = actions.PurgeAllPolicies(ctx); err != nil {
		return newExitError(c, err)
	}

	fmt.Fprintf(c.App.Writer, "All keys purged for %q.\n", ctx.Mount.Path)
	fmt.Fprintf(c.App.Writer, "Filesystem %q should now be unmounted.\n", ctx.Mount.Path)
	return nil
}

// Status is a command with three subcommands relating to printing out status.
var Status = cli.Command{
	Name:      "status",
	ArgsUsage: fmt.Sprintf("[%s]", pathArg),
	Usage:     "print the global, filesystem, or file status",
	Description: fmt.Sprintf(`This command prints out the global,
		per-filesystem, or per-file status.

		(1) When used without %[1]s, print all of the currently visible
		filesystems which support use with fscrypt. For each of
		the filesystems, this command also notes if they are actually
		being used by fscrypt. This command will fail if no there is no
		support for fscrypt anywhere on the system.

		(2) When %[1]s is a filesystem mountpoint, list information
		about all the policies and protectors which exist on %[1]s. This
		command will fail if %[1]s is not being used with fscrypt. For
		each policy, this command also notes if the policy is currently
		unlocked.

		(3) When %[1]s is just a normal path, print information about
		the policy being used on %[1]s and the protectors protecting
		this file or directory. This command will fail if %[1]s is not
		setup for encryption with fscrypt.`, pathArg),
	Action: statusAction,
}

func statusAction(c *cli.Context) error {
	var err error

	switch c.NArg() {
	case 0:
		// Case (1) - global status
		err = writeGlobalStatus(c.App.Writer)
	case 1:
		path := c.Args().Get(0)
		ctx, mntErr := actions.NewContextFromMountpoint(path)

		switch errors.Cause(mntErr) {
		case nil:
			// Case (2) - mountpoint status
			err = writeFilesystemStatus(c.App.Writer, ctx)
		case filesystem.ErrNotAMountpoint:
			// Case (3) - file or directory status
			err = writePathStatus(c.App.Writer, path)
		default:
			err = mntErr
		}
	default:
		return expectedArgsErr(c, 1, true)
	}

	if err != nil {
		return newExitError(c, err)
	}
	return nil
}

// Metadata is a collection of commands for manipulating the metadata files.
var Metadata = cli.Command{
	Name:  "metadata",
	Usage: "[ADVANCED] manipulate the policy or protector metadata",
	Description: `These commands allow a user to directly create, delete, or
		change the metadata files. It is important to note that using
		these commands, especially the destructive ones, can make files
		encrypted with fscrypt unavailable. For instance, deleting a
		policy effectively deletes all the contents of the corresponding
		directory. Some example use cases include:

		(1) Directly creating protectors and policies using the "create"
		subcommand. These can then be applied with "fscrypt encrypt".

		(2) Changing the passphrase for a passphrase protector using the
		"change-passphrase" subcommand.

		(3) Creating a policy protected with multiple protectors using
		the "create policy" and "add-protector-to-policy" subcommands.

		(4) Changing the protector protecting a policy using the
		"add-protector-to-policy" and "remove-protector-from-policy"
		subcommands.`,
	Subcommands: []cli.Command{createMetadata, destoryMetadata, changePassphrase,
		addProtectorToPolicy, removeProtectorFromPolicy, dumpMetadata},
}

var createMetadata = cli.Command{
	Name:        "create",
	ArgsUsage:   fmt.Sprintf("[protector | policy] %s", mountpointArg),
	Usage:       "manually create new metadata on a filesystem",
	Subcommands: []cli.Command{createProtector, createPolicy},
}

var createProtector = cli.Command{
	Name:      "protector",
	ArgsUsage: mountpointArg,
	Usage:     "create a new protector on a filesystem",
	Description: fmt.Sprintf(`This command creates a new protector on %s
		that does not (yet) protect any policy. After creation, the user
		can use %s with "fscrypt encrypt" to protect a directory with
		this new protector. The creation process is identical to the
		first step of "fscrypt encrypt" when the user has requested to
		create a new passphrase. The user will be prompted for the
		source, name, and secret data for the new protector (when
		applicable). As with "fscrypt encrypt", these prompts can be
		disabled with the appropriate flags.`, mountpointArg,
		shortDisplay(protectorFlag)),
	Flags:  []cli.Flag{sourceFlag, nameFlag, keyFileFlag},
	Action: createProtectorAction,
}

func createProtectorAction(c *cli.Context) error {
	if c.NArg() != 1 {
		return expectedArgsErr(c, 1, false)
	}

	ctx, err := actions.NewContextFromMountpoint(c.Args().Get(0))
	if err != nil {
		return newExitError(c, err)
	}

	prompt := fmt.Sprintf("Create new protector on %q", ctx.Mount.Path)
	if err := askConfirmation(prompt, true, ""); err != nil {
		return newExitError(c, err)
	}

	protector, err := createProtectorFromContext(ctx)
	if err != nil {
		return newExitError(c, err)
	}
	protector.Lock()

	fmt.Fprintf(c.App.Writer, "Protector %s created on filesystem %q.\n",
		protector.Descriptor(), ctx.Mount.Path)
	return nil
}

var createPolicy = cli.Command{
	Name:      "policy",
	ArgsUsage: fmt.Sprintf("%s %s", mountpointArg, shortDisplay(protectorFlag)),
	Usage:     "create a new protector on a filesystem",
	Description: fmt.Sprintf(`This command creates a new protector on %s
		that has not (yet) been applied to any directory. After
		creation, the user can use %s with "fscrypt encrypt" to encrypt
		a directory with this new policy. As all policies must be
		protected with at least one protector, this command requires
		specifying one with %s. To create a policy protected by many
		protectors, use this command and "fscrypt metadata
		add-protector-to-policy".`, mountpointArg,
		shortDisplay(policyFlag), shortDisplay(protectorFlag)),
	Flags:  []cli.Flag{protectorFlag, keyFileFlag},
	Action: createPolicyAction,
}

func createPolicyAction(c *cli.Context) error {
	if c.NArg() != 1 {
		return expectedArgsErr(c, 1, false)
	}

	ctx, err := actions.NewContextFromMountpoint(c.Args().Get(0))
	if err != nil {
		return newExitError(c, err)
	}

	if err := checkRequiredFlags(c, []*stringFlag{protectorFlag}); err != nil {
		return err
	}
	protector, err := getProtectorFromFlag(protectorFlag.Value)
	if err != nil {
		return newExitError(c, err)
	}
	if err := protector.Unlock(existingKeyFn); err != nil {
		return newExitError(c, err)
	}
	defer protector.Lock()

	prompt := fmt.Sprintf("Create new policy on %q", ctx.Mount.Path)
	if err := askConfirmation(prompt, true, ""); err != nil {
		return newExitError(c, err)
	}

	policy, err := actions.CreatePolicy(ctx, protector)
	if err != nil {
		return newExitError(c, err)
	}
	policy.Lock()

	fmt.Fprintf(c.App.Writer, "Policy %s created on filesystem %q.\n",
		policy.Descriptor(), ctx.Mount.Path)
	return nil
}

var destoryMetadata = cli.Command{
	Name: "destroy",
	ArgsUsage: fmt.Sprintf("[%s | %s | %s]", shortDisplay(protectorFlag),
		shortDisplay(policyFlag), mountpointArg),
	Usage: "delete a filesystem's, protector's, or policy's metadata",
	Description: fmt.Sprintf(`This command can be used to perform three
		different destructive operations. Note that in all of these
		cases, data will usually be lost, so use with care.

		(1) If used with %[1]s, this command deletes all the data
		associated with that protector. This means all directories
		protected with that protector will become PERMANENTLY
		inaccessible (unless the policies were protected by multiple
		protectors).

		(2) If used with %[2]s, this command deletes all the data
		associated with that policy. This means all directories (usually
		just one) using this policy will become PERMANENTLY
		inaccessible.

		(3) If used with %[3]s, all the metadata on that filesystem will
		be deleted, causing all directories on that filesystem using
		fscrypt to become PERMANENTLY inaccessible. To start using this
		directory again, "fscrypt setup %[3]s" will need to be rerun.`,
		shortDisplay(protectorFlag), shortDisplay(policyFlag),
		mountpointArg),
	Flags:  []cli.Flag{protectorFlag, policyFlag, forceFlag},
	Action: destoryMetadataAction,
}

func destoryMetadataAction(c *cli.Context) error {
	switch c.NArg() {
	case 0:
		switch {
		case protectorFlag.Value != "":
			// Case (1) - protector destroy
			protector, err := getProtectorFromFlag(protectorFlag.Value)
			if err != nil {
				return newExitError(c, err)
			}

			prompt := fmt.Sprintf("Destroy protector %s on %q?",
				protector.Descriptor(), protector.Context.Mount.Path)
			warning := "All files protected only with this protector will be lost!!"
			if err := askConfirmation(prompt, false, warning); err != nil {
				return newExitError(c, err)
			}
			if err := protector.Destroy(); err != nil {
				return newExitError(c, err)
			}

			fmt.Fprintf(c.App.Writer, "Protector %s deleted from filesystem %q.\n",
				protector.Descriptor(), protector.Context.Mount.Path)
		case policyFlag.Value != "":
			// Case (2) - policy destroy
			policy, err := getPolicyFromFlag(policyFlag.Value)
			if err != nil {
				return newExitError(c, err)
			}

			prompt := fmt.Sprintf("Destroy policy %s on %q?",
				policy.Descriptor(), policy.Context.Mount.Path)
			warning := "All files using this policy will be lost!!"
			if err := askConfirmation(prompt, false, warning); err != nil {
				return newExitError(c, err)
			}
			if err := policy.Destroy(); err != nil {
				return newExitError(c, err)
			}

			fmt.Fprintf(c.App.Writer, "Policy %s deleted from filesystem %q.\n",
				policy.Descriptor(), policy.Context.Mount.Path)
		default:
			message := fmt.Sprintf("Must specify one of: %s, %s, or %s",
				mountpointArg,
				shortDisplay(protectorFlag),
				shortDisplay(policyFlag))
			return &usageError{c, message}
		}
	case 1:
		// Case (3) - mountpoint destroy
		path := c.Args().Get(0)
		ctx, err := actions.NewContextFromMountpoint(path)
		if err != nil {
			return newExitError(c, err)
		}

		prompt := fmt.Sprintf("Destroy all the metadata on %q?", ctx.Mount.Path)
		warning := "All the encrypted files on this filesystem will be lost!!"
		if err := askConfirmation(prompt, false, warning); err != nil {
			return newExitError(c, err)
		}
		if err := ctx.Mount.RemoveAllMetadata(); err != nil {
			return newExitError(c, err)
		}

		fmt.Fprintf(c.App.Writer, "All metadata on %q deleted.\n", ctx.Mount.Path)
	default:
		return expectedArgsErr(c, 1, true)
	}
	return nil
}

var changePassphrase = cli.Command{
	Name:      "change-passphrase",
	ArgsUsage: shortDisplay(protectorFlag),
	Usage:     "change the passphrase used for a protector",
	Description: `This command takes a specified passphrase protector and
		changes the corresponding passphrase. Note that this does not
		create or destroy any protectors.`,
	Flags:  []cli.Flag{protectorFlag},
	Action: changePassphraseAction,
}

func changePassphraseAction(c *cli.Context) error {
	if c.NArg() != 0 {
		return expectedArgsErr(c, 0, false)
	}
	if err := checkRequiredFlags(c, []*stringFlag{protectorFlag}); err != nil {
		return err
	}

	protector, err := getProtectorFromFlag(protectorFlag.Value)
	if err != nil {
		return newExitError(c, err)
	}
	if err := protector.Unlock(oldExistingKeyFn); err != nil {
		return newExitError(c, err)
	}
	defer protector.Lock()
	if err := protector.Rewrap(newCreateKeyFn); err != nil {
		return newExitError(c, err)
	}

	fmt.Fprintf(c.App.Writer, "Passphrase for protector %s successfully changed.\n",
		protector.Descriptor())
	return nil
}

var addProtectorToPolicy = cli.Command{
	Name:      "add-protector-to-policy",
	ArgsUsage: fmt.Sprintf("%s %s", shortDisplay(protectorFlag), shortDisplay(policyFlag)),
	Usage:     "start protecting a policy with some protector",
	Description: `This command changes the specified policy to be
		protected with the specified protector. This means that any
		directories using this policy will now be accessible with this
		protector. This command will fail if the policy is already
		protected with this protector.`,
	Flags:  []cli.Flag{protectorFlag, policyFlag, unlockWithFlag, keyFileFlag},
	Action: addProtectorAction,
}

func addProtectorAction(c *cli.Context) error {
	if c.NArg() != 0 {
		return expectedArgsErr(c, 0, false)
	}
	if err := checkRequiredFlags(c, []*stringFlag{protectorFlag, policyFlag}); err != nil {
		return err
	}

	protector, err := getProtectorFromFlag(protectorFlag.Value)
	if err != nil {
		return newExitError(c, err)
	}
	policy, err := getPolicyFromFlag(policyFlag.Value)
	if err != nil {
		return newExitError(c, err)
	}
	// Sanity check before unlocking everything
	if err := policy.AddProtector(protector); errors.Cause(err) != actions.ErrLocked {
		return newExitError(c, err)
	}

	prompt := fmt.Sprintf("Protect policy %s with protector %s?",
		policy.Descriptor(), protector.Descriptor())
	warning := "All files using this policy will be accessible with this protector!!"
	if err := askConfirmation(prompt, true, warning); err != nil {
		return newExitError(c, err)
	}

	if err := protector.Unlock(existingKeyFn); err != nil {
		return newExitError(c, err)
	}
	if err := policy.Unlock(optionFn, existingKeyFn); err != nil {
		return newExitError(c, err)
	}
	if err := policy.AddProtector(protector); err != nil {
		return newExitError(c, err)
	}

	fmt.Fprintf(c.App.Writer, "Protector %s now protecting policy %s.\n",
		protector.Descriptor(), policy.Descriptor())
	return nil
}

var removeProtectorFromPolicy = cli.Command{
	Name:      "remove-protector-from-policy",
	ArgsUsage: fmt.Sprintf("%s %s", shortDisplay(protectorFlag), shortDisplay(policyFlag)),
	Usage:     "stop protecting a policy with some protector",
	Description: `This command changes the specified policy to no longer be
		protected with the specified protector. This means that any
		directories using this policy will cannot be accessed with this
		protector. This command will fail if the policy not already
		protected with this protector or if it is the policy's only
		protector.`,
	Flags:  []cli.Flag{protectorFlag, policyFlag, forceFlag},
	Action: removeProtectorAction,
}

func removeProtectorAction(c *cli.Context) error {
	if c.NArg() != 0 {
		return expectedArgsErr(c, 0, false)
	}
	if err := checkRequiredFlags(c, []*stringFlag{protectorFlag, policyFlag}); err != nil {
		return err
	}

	// We do not need to unlock anything for this operation
	protector, err := getProtectorFromFlag(protectorFlag.Value)
	if err != nil {
		return newExitError(c, err)
	}
	policy, err := getPolicyFromFlag(policyFlag.Value)
	if err != nil {
		return newExitError(c, err)
	}

	prompt := fmt.Sprintf("Stop protecting policy %s with protector %s?",
		policy.Descriptor(), protector.Descriptor())
	warning := "All files using this policy will NO LONGER be accessible with this protector!!"
	if err := askConfirmation(prompt, false, warning); err != nil {
		return newExitError(c, err)
	}

	if err := policy.RemoveProtector(protector); err != nil {
		return newExitError(c, err)
	}

	fmt.Fprintf(c.App.Writer, "Protector %s no longer protecting policy %s.\n",
		protector.Descriptor(), policy.Descriptor())
	return nil
}

var dumpMetadata = cli.Command{
	Name:      "dump",
	ArgsUsage: fmt.Sprintf("[%s | %s]", shortDisplay(protectorFlag), shortDisplay(policyFlag)),
	Usage:     "print debug data for a policy or protector",
	Description: fmt.Sprintf(`This commands dumps all of the debug data for
		a protector (if %s is used) or policy (if %s is used). This data
		includes the data pulled from the %q config file, the
		appropriate mountpoint data, and any options for the policy or
		hashing costs for the protector. Any cryptographic keys are
		wiped and are not printed out.`, shortDisplay(protectorFlag),
		shortDisplay(policyFlag), actions.ConfigFileLocation),
	Flags:  []cli.Flag{protectorFlag, policyFlag},
	Action: dumpMetadataAction,
}

func dumpMetadataAction(c *cli.Context) error {
	switch {
	case protectorFlag.Value != "":
		// Case (1) - protector print
		protector, err := getProtectorFromFlag(protectorFlag.Value)
		if err != nil {
			return newExitError(c, err)
		}
		fmt.Fprintln(c.App.Writer, protector)
	case policyFlag.Value != "":
		// Case (2) - policy print
		policy, err := getPolicyFromFlag(policyFlag.Value)
		if err != nil {
			return newExitError(c, err)
		}
		fmt.Fprintln(c.App.Writer, policy)
	default:
		message := fmt.Sprintf("Must specify one of: %s or %s",
			shortDisplay(protectorFlag),
			shortDisplay(policyFlag))
		return &usageError{c, message}
	}
	return nil
}

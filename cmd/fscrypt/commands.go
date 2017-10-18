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
	"log"
	"os"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/cmd"
	"github.com/google/fscrypt/metadata"
)

// var Setup = cli.Command{
// 	Name:      "setup",
// 	ArgsUsage: fmt.Sprintf("[%s]", mountpointArg),
// 	Usage:     "perform global setup or filesystem setup",
// 	Description: fmt.Sprintf(`This command creates fscrypt's global config
// 		file or enables fscrypt on a filesystem.

// 		(1) When used without %[1]s, create the parameters in %[2]s.
// 		This is primarily used to configure the passphrase hashing
// 		parameters to the appropriate hardness (as determined by %[3]s).
// 		Being root is required to write the config file.

// 		(2) When used with %[1]s, enable fscrypt on %[1]s. This involves
// 		creating the necessary folders on the filesystem which will hold
// 		the metadata structures. Begin root may be required to create
// 		these folders.`, mountpointArg, actions.ConfigFileLocation,
// 		shortDisplay(timeTargetFlag)),
// 	Flags:  []cli.Flag{timeTargetFlag, legacyFlag, forceFlag},
// 	Action: setupAction,
// }

// var Encrypt = cli.Command{
// 	Name:      "encrypt",
// 	ArgsUsage: directoryArg,
// 	Usage:     "enable filesystem encryption for a directory",
// 	Description: fmt.Sprintf(`This command enables filesystem encryption on
// 		%[1]s. This may involve creating a new policy (if one is not
// 		specified with %[2]s) or a new protector (if one is not
// 		specified with %[3]s). This command requires that the
// 		corresponding filesystem has been setup with "fscrypt setup
// 		%[4]s". By default, after %[1]s is setup, it is unlocked and can
// 		immediately be used.`, directoryArg, shortDisplay(policyFlag),
// 		shortDisplay(protectorFlag), mountpointArg),
// 	Flags: []cli.Flag{policyFlag, unlockWithFlag, protectorFlag, sourceFlag,
// 		userFlag, nameFlag, keyFileFlag, skipUnlockFlag},
// 	Action: encryptAction,
// }

// encryptPath sets up encryption on path and provisions the policy to the
// keyring unless --skip-unlock is used. On failure, an error is returned, any
// metadata creation is reverted, and the directory is unmodified.
func encryptPath(path string) (err error) {
	target, err := parseUserFlag(!skipUnlockFlag.Value)
	if err != nil {
		return
	}
	ctx, err := actions.NewContextFromPath(path, target)
	if err != nil {
		return
	}
	if err = checkEncryptable(ctx, path); err != nil {
		return
	}

	var policy *actions.Policy
	if policyFlag.Value != "" {
		log.Printf("getting policy for %q", path)

		policy, err = getPolicyFromFlag(policyFlag.Value, ctx.TargetUser)
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

	log.Printf("ensuring %s supports encryption and filesystem is using fscrypt", path)
	switch _, err := actions.GetPolicyFromPath(ctx, path); errors.Cause(err) {
	case metadata.ErrNotEncrypted:
		// We are not encrypted. Finally, we check that the filesystem
		// supports encryption
		return ctx.Mount.CheckSupport()
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
		protector, err := getProtectorFromFlag(protectorFlag.Value, ctx.TargetUser)
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

	shouldCreate, err := cmd.AskQuestion("Should we create a new protector?", false)
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

// var Unlock = cli.Command{
// 	Name:      "unlock",
// 	ArgsUsage: directoryArg,
// 	Usage:     "unlock an encrypted directory",
// 	Description: fmt.Sprintf(`This command takes %s, a directory setup for
// 		use with fscrypt, and unlocks the directory by passing the
// 		appropriate key into the keyring. This requires unlocking one of
// 		the protectors protecting this directory (either by selecting a
// 		protector or specifying one with %s). This directory will be
// 		locked again upon reboot, or after running "fscrypt purge" and
// 		unmounting the corresponding filesystem.`, directoryArg,
// 		shortDisplay(unlockWithFlag)),
// 	Flags:  []cli.Flag{unlockWithFlag, keyFileFlag, userFlag},
// 	Action: unlockAction,
// }

func unlockPath(path string) error {
	target, err := parseUserFlag(true)
	if err != nil {
		return err
	}
	ctx, err := actions.NewContextFromPath(path, target)
	if err != nil {
		return err
	}

	log.Printf("performing sanity checks")
	// Ensure path is encrypted and filesystem is using fscrypt.
	policy, err := actions.GetPolicyFromPath(ctx, path)
	if err != nil {
		return err
	}
	// Check if directory is already unlocked
	if policy.IsProvisioned() {
		log.Printf("policy %s is already provisioned", policy.Descriptor())
		return errors.Wrapf(ErrPolicyUnlocked, path)
	}

	if err := policy.Unlock(optionFn, existingKeyFn); err != nil {
		return err
	}
	defer policy.Lock()

	return policy.Provision()
}

// var Purge = cli.Command{
// 	Name:      "purge",
// 	ArgsUsage: mountpointArg,
// 	Usage:     "Remove a filesystem's keys",
// 	Description: fmt.Sprintf(`This command removes a user's policy keys for
// 		directories on %[1]s. This is intended to lock all files and
// 		directories encrypted by the user on %[1]s, in that unlocking
// 		them for reading will require providing a key again. However,
// 		there are four important things to note about this command:

// 		(1) When run with the default options, this command also clears
// 		the reclaimable dentries and inodes, so that the encrypted files
// 		and directories will no longer be visible. However, this
// 		requires root privileges. Note that any open file descriptors to
// 		plaintext data will not be affected by this command.

// 		(2) When run with %[2]s=false, the keyring is cleared and root
// 		permissions are not required, but recently accessed encrypted
// 		directories and files will remain cached for some time. Because
// 		of this, after purging a filesystem's keys in this manner, it
// 		is recommended to unmount the filesystem.

// 		(3) When run as root, this command removes the policy keys for
// 		all users. However, this will only work if the PAM module has
// 		been enabled. Otherwise, only root's keys may be removed.

// 		(4) Even after unmounting the filesystem or clearing the
// 		caches, the kernel may keep contents of files in memory. This
// 		means direct memory access (either though physical compromise or
// 		a kernel exploit) could compromise encrypted data. This weakness
// 		can be eliminated by cycling the power or mitigated by using
// 		page cache and slab cache poisoning.`, mountpointArg,
// 		shortDisplay(dropCachesFlag)),
// 	Flags:  []cli.Flag{forceFlag, dropCachesFlag, userFlag},
// 	Action: purgeAction,
// }

// var Status = cli.Command{
// 	Name:      "status",
// 	ArgsUsage: fmt.Sprintf("[%s]", pathArg),
// 	Usage:     "print the global, filesystem, or file status",
// 	Description: fmt.Sprintf(`This command prints out the global,
// 		per-filesystem, or per-file status.

// 		(1) When used without %[1]s, print all of the currently visible
// 		filesystems which support use with fscrypt. For each of
// 		the filesystems, this command also notes if they are actually
// 		being used by fscrypt. This command will fail if no there is no
// 		support for fscrypt anywhere on the system.

// 		(2) When %[1]s is a filesystem mountpoint, list information
// 		about all the policies and protectors which exist on %[1]s. This
// 		command will fail if %[1]s is not being used with fscrypt. For
// 		each policy, this command also notes if the policy is currently
// 		unlocked.

// 		(3) When %[1]s is just a normal path, print information about
// 		the policy being used on %[1]s and the protectors protecting
// 		this file or directory. This command will fail if %[1]s is not
// 		setup for encryption with fscrypt.`, pathArg),
// 	Action: statusAction,
// }

// var Metadata = cli.Command{
// 	Name:  "metadata",
// 	Usage: "[ADVANCED] manipulate the policy or protector metadata",
// 	Description: `These commands allow a user to directly create, delete, or
// 		change the metadata files. It is important to note that using
// 		these commands, especially the destructive ones, can make files
// 		encrypted with fscrypt unavailable. For instance, deleting a
// 		policy effectively deletes all the contents of the corresponding
// 		directory. Some example use cases include:

// 		(1) Directly creating protectors and policies using the "create"
// 		subcommand. These can then be applied with "fscrypt encrypt".

// 		(2) Changing the passphrase for a passphrase protector using the
// 		"change-passphrase" subcommand.

// 		(3) Creating a policy protected with multiple protectors using
// 		the "create policy" and "add-protector-to-policy" subcommands.

// 		(4) Changing the protector protecting a policy using the
// 		"add-protector-to-policy" and "remove-protector-from-policy"
// 		subcommands.`,
// 	Subcommands: []cli.Command{createMetadata, destoryMetadata, changePassphrase,
// 		addProtectorToPolicy, removeProtectorFromPolicy, dumpMetadata},
// }

// var createProtector = cli.Command{
// 	Name:      "protector",
// 	ArgsUsage: mountpointArg,
// 	Usage:     "create a new protector on a filesystem",
// 	Description: fmt.Sprintf(`This command creates a new protector on %s
// 		that does not (yet) protect any policy. After creation, the user
// 		can use %s with "fscrypt encrypt" to protect a directory with
// 		this new protector. The creation process is identical to the
// 		first step of "fscrypt encrypt" when the user has requested to
// 		create a new passphrase. The user will be prompted for the
// 		source, name, and secret data for the new protector (when
// 		applicable). As with "fscrypt encrypt", these prompts can be
// 		disabled with the appropriate flags.`, mountpointArg,
// 		shortDisplay(protectorFlag)),
// 	Flags:  []cli.Flag{sourceFlag, nameFlag, keyFileFlag, userFlag},
// 	Action: createProtectorAction,
// }

// var createPolicy = cli.Command{
// 	Name:      "policy",
// 	ArgsUsage: fmt.Sprintf("%s %s", mountpointArg, shortDisplay(protectorFlag)),
// 	Usage:     "create a new protector on a filesystem",
// 	Description: fmt.Sprintf(`This command creates a new protector on %s
// 		that has not (yet) been applied to any directory. After
// 		creation, the user can use %s with "fscrypt encrypt" to encrypt
// 		a directory with this new policy. As all policies must be
// 		protected with at least one protector, this command requires
// 		specifying one with %s. To create a policy protected by many
// 		protectors, use this command and "fscrypt metadata
// 		add-protector-to-policy".`, mountpointArg,
// 		shortDisplay(policyFlag), shortDisplay(protectorFlag)),
// 	Flags:  []cli.Flag{protectorFlag, keyFileFlag},
// 	Action: createPolicyAction,
// }

//// ***** WIP END/BEGIN HERE *****

// var destoryMetadata = cli.Command{
// 	Name: "destroy",
// 	ArgsUsage: fmt.Sprintf("[%s | %s | %s]", shortDisplay(protectorFlag),
// 		shortDisplay(policyFlag), mountpointArg),
// 	Usage: "delete a filesystem's, protector's, or policy's metadata",
// 	Description: fmt.Sprintf(`This command can be used to perform three
// 		different destructive operations. Note that in all of these
// 		cases, data will usually be lost, so use with care.

// 		(1) If used with %[1]s, this command deletes all the data
// 		associated with that protector. This means all directories
// 		protected with that protector will become PERMANENTLY
// 		inaccessible (unless the policies were protected by multiple
// 		protectors).

// 		(2) If used with %[2]s, this command deletes all the data
// 		associated with that policy. This means all directories (usually
// 		just one) using this policy will become PERMANENTLY
// 		inaccessible.

// 		(3) If used with %[3]s, all the metadata on that filesystem will
// 		be deleted, causing all directories on that filesystem using
// 		fscrypt to become PERMANENTLY inaccessible. To start using this
// 		directory again, "fscrypt setup %[3]s" will need to be rerun.`,
// 		shortDisplay(protectorFlag), shortDisplay(policyFlag),
// 		mountpointArg),
// 	Flags:  []cli.Flag{protectorFlag, policyFlag, forceFlag},
// 	Action: destoryMetadataAction,
// }

// var changePassphrase = cli.Command{
// 	Name:      "change-passphrase",
// 	ArgsUsage: shortDisplay(protectorFlag),
// 	Usage:     "change the passphrase used for a protector",
// 	Description: `This command takes a specified passphrase protector and
// 		changes the corresponding passphrase. Note that this does not
// 		create or destroy any protectors.`,
// 	Flags:  []cli.Flag{protectorFlag},
// 	Action: changePassphraseAction,
// }

// var addProtectorToPolicy = cli.Command{
// 	Name:      "add-protector-to-policy",
// 	ArgsUsage: fmt.Sprintf("%s %s", shortDisplay(protectorFlag), shortDisplay(policyFlag)),
// 	Usage:     "start protecting a policy with some protector",
// 	Description: `This command changes the specified policy to be
// 		protected with the specified protector. This means that any
// 		directories using this policy will now be accessible with this
// 		protector. This command will fail if the policy is already
// 		protected with this protector.`,
// 	Flags:  []cli.Flag{protectorFlag, policyFlag, unlockWithFlag, keyFileFlag},
// 	Action: addProtectorAction,
// }

// var removeProtectorFromPolicy = cli.Command{
// 	Name:      "remove-protector-from-policy",
// 	ArgsUsage: fmt.Sprintf("%s %s", shortDisplay(protectorFlag), shortDisplay(policyFlag)),
// 	Usage:     "stop protecting a policy with some protector",
// 	Description: `This command changes the specified policy to no longer be
// 		protected with the specified protector. This means that any
// 		directories using this policy will cannot be accessed with this
// 		protector. This command will fail if the policy not already
// 		protected with this protector or if it is the policy's only
// 		protector.`,
// 	Flags:  []cli.Flag{protectorFlag, policyFlag, forceFlag},
// 	Action: removeProtectorAction,
// }

// var dumpMetadata = cli.Command{
// 	Name:      "dump",
// 	ArgsUsage: fmt.Sprintf("[%s | %s]", shortDisplay(protectorFlag), shortDisplay(policyFlag)),
// 	Usage:     "print debug data for a policy or protector",
// 	Description: fmt.Sprintf(`This commands dumps all of the debug data for
// 		a protector (if %s is used) or policy (if %s is used). This data
// 		includes the data pulled from the %q config file, the
// 		appropriate mountpoint data, and any options for the policy or
// 		hashing costs for the protector. Any cryptographic keys are
// 		wiped and are not printed out.`, shortDisplay(protectorFlag),
// 		shortDisplay(policyFlag), actions.ConfigFileLocation),
// 	Flags:  []cli.Flag{protectorFlag, policyFlag},
// 	Action: dumpMetadataAction,
// }

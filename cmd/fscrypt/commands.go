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

	"fscrypt/actions"
	"fscrypt/metadata"
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

		var protector *actions.Protector
		protector, err = selectOrCreateProtector(ctx)
		// Successfully created protector should be reverted on failure.
		if err != nil {
			return
		}
		defer func() {
			protector.Lock()
			if err != nil {
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
		policy.Deprovision()
		if err != nil {
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
// protector or select and existing one. The created return value is true if we
// created a new protector.
func selectOrCreateProtector(ctx *actions.Context) (*actions.Protector, error) {
	if protectorFlag.Value != "" {
		return getProtectorFromFlag(protectorFlag.Value)
	}

	options, err := expandedProtectorOptions(ctx)
	if err != nil {
		return nil, err
	}

	// Having no existing options to choose from or using creation-only
	// flags indicates we should make a new protector.
	if len(options) == 0 || nameFlag.Value != "" || sourceFlag.Value != "" {
		return createProtectorFromContext(ctx)
	}

	created, err := askQuestion("Should we create a new protector?", false)
	if err != nil {
		return nil, err
	}
	if created {
		return createProtectorFromContext(ctx)
	}

	log.Print("finding an existing protector to use")
	return selectExistingProtector(ctx, options)
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

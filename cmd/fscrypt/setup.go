/*
 * setup.go - File containing the functionality for initializing directories and
 * the global config file.
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
	"io"
	"os"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/util"
)

// createGlobalConfig creates (or overwrites) the global config file
func createGlobalConfig(w io.Writer, path string) error {
	if !util.IsUserRoot() {
		return ErrMustBeRoot
	}

	// If the config file already exists, ask to replace it
	_, err := os.Stat(path)
	switch {
	case err == nil:
		err = askConfirmation(fmt.Sprintf("Replace %q?", path), false, "")
		if err == nil {
			err = os.Remove(path)
		}
	case os.IsNotExist(err):
		err = nil
	}
	if err != nil {
		return err
	}

	// v2 encryption policies are recommended, so set policy_version 2 when
	// the kernel supports it. v2 policies are supported by upstream Linux
	// v5.4 and later. For now we simply check the kernel version. Ideally
	// we'd instead check whether setting a v2 policy actually works, in
	// order to also detect backports of the kernel patches. However, that's
	// hard because from this context (creating /etc/fscrypt.conf) we may
	// not yet have access to a filesystem that supports encryption.
	var policyVersion int64
	if util.IsKernelVersionAtLeast(5, 4) {
		fmt.Fprintln(w, "Defaulting to policy_version 2 because kernel supports it.")
		policyVersion = 2
	} else {
		fmt.Fprintln(w, "Defaulting to policy_version 1 because kernel doesn't support v2.")
	}
	fmt.Fprintln(w, "Customizing passphrase hashing difficulty for this system...")
	err = actions.CreateConfigFile(timeTargetFlag.Value, policyVersion)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "Created global config file at %q.\n", path)
	return nil
}

// setupFilesystem creates the directories for a filesystem to use fscrypt.
func setupFilesystem(w io.Writer, path string) error {
	ctx, err := actions.NewContextFromMountpoint(path, nil)
	if err != nil {
		return err
	}
	username := ctx.TargetUser.Username

	err = ctx.Mount.CheckSetup()
	if err == nil {
		return &filesystem.ErrAlreadySetup{Mount: ctx.Mount}
	}
	if _, ok := err.(*filesystem.ErrNotSetup); !ok {
		return err
	}

	allUsers := allUsersSetupFlag.Value
	if !allUsers {
		thisFilesystem := "this filesystem"
		if ctx.Mount.Path == "/" {
			thisFilesystem = "the root filesystem"
		}
		prompt := fmt.Sprintf(`Allow users other than %s to create
fscrypt metadata on %s? (See
https://github.com/google/fscrypt#setting-up-fscrypt-on-a-filesystem)`,
			username, thisFilesystem)
		allUsers, err = askQuestion(wrapText(prompt, 0), false)
		if err != nil {
			return err
		}
	}
	var setupMode filesystem.SetupMode
	if allUsers {
		setupMode = filesystem.WorldWritable
	} else {
		setupMode = filesystem.SingleUserWritable
	}
	if err = ctx.Mount.Setup(setupMode); err != nil {
		return err
	}

	if allUsers {
		fmt.Fprintf(w, "Metadata directories created at %q, writable by everyone.\n",
			ctx.Mount.BaseDir())
	} else {
		fmt.Fprintf(w, "Metadata directories created at %q, writable by %s only.\n",
			ctx.Mount.BaseDir(), username)
	}
	return nil
}

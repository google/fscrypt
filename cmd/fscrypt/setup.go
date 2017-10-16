/*
 * strings.go - File containing the functionality initializing directories and
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
	"os"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/cmd"
)

// createGlobalConfig creates (or overwrites) the global config file
func createGlobalConfig(path string) error {
	if err := cmd.CheckIfRoot(); err != nil {
		return err
	}

	// Ask to create or replace the config file
	_, err := os.Stat(path)
	switch {
	case err == nil:
		err = cmd.AskConfirmation(fmt.Sprintf("Replace %q?", path), "", false)
		if err == nil {
			err = os.Remove(path)
		}
	case os.IsNotExist(err):
		err = cmd.AskConfirmation(fmt.Sprintf("Create %q?", path), "", true)
	}
	if err != nil {
		return err
	}

	fmt.Fprintln(cmd.Output, "Customizing passphrase hashing difficulty for this system...")
	err = actions.CreateConfigFile(timeTargetFlag.Value, legacyFlag.Value)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.Output, "Created global config file at %q.\n", path)
	return nil
}

// setupFilesystem creates the directories for a filesystem to use fscrypt.
func setupFilesystem(path string) error {
	ctx, err := actions.NewContextFromMountpoint(path, nil)
	if err != nil {
		return err
	}

	if err = ctx.Mount.Setup(); err != nil {
		return err
	}

	fmt.Fprintf(Output, "Metadata directories created at %q.\n", ctx.Mount.BaseDir())
	fmt.Fprintf(Output, "Filesystem %q (%s) ready for use with %s encryption.\n",
		ctx.Mount.Path, ctx.Mount.Device, ctx.Mount.Filesystem)
	return nil
}

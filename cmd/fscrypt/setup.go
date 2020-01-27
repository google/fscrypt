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

	fmt.Fprintln(w, "Customizing passphrase hashing difficulty for this system...")
	err = actions.CreateConfigFile(timeTargetFlag.Value, legacyFlag.Value)
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

	if err = ctx.Mount.Setup(); err != nil {
		return err
	}

	fmt.Fprintf(w, "Metadata directories created at %q.\n", ctx.Mount.BaseDir())
	return nil
}

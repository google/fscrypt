/*
 * context.go - top-level interface to fscrypt packages
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

// Package actions is the high-level interface to the fscrypt packages. The
// functions here roughly correspond with commands for the tool in cmd/fscrypt.
// All of the actions include a significant amount of logging, so that good
// output can be provided for cmd/fscrypt's verbose mode.
// The top-level actions currently include:
//	- Creating a new config file
//	- Creating a context on which to perform actions
//	- Creating, unlocking, and modifying Protectors
//	- Creating, unlocking, and modifying Policies
package actions

import (
	"errors"
	"fmt"
	"log"

	"fscrypt/filesystem"
	"fscrypt/metadata"
	"fscrypt/util"
)

// Errors relating to Config files or Config structures.
var (
	ErrNoConfigFile     = fmt.Errorf("config file %q does not exist", ConfigFileLocation)
	ErrBadConfigFile    = fmt.Errorf("config file %q has invalid data", ConfigFileLocation)
	ErrConfigFileExists = fmt.Errorf("config file %q already exists", ConfigFileLocation)
	ErrBadConfig        = errors.New("invalid Config structure provided")
)

// Context contains the necessary global state to perform most of fscrypt's
// actions. It contains a config struct, which is loaded from the global config
// file, but can be edited manually. A context is specific to a filesystem, and
// all actions to add, edit, remove, and apply Protectors and Policies are done
// relative to that filesystem.
type Context struct {
	Config *metadata.Config
	Mount  *filesystem.Mount
}

// NewContextFromPath makes a context for the filesystem containing the
// specified path and whose Config is loaded from the global config file. On
// success, the Context contains a valid Config and Mount.
func NewContextFromPath(path string) (ctx *Context, err error) {
	ctx = new(Context)

	if ctx.Mount, err = filesystem.FindMount(path); err != nil {
		err = util.UnderlyingError(err)
		return
	}

	if ctx.Config, err = getConfig(); err != nil {
		return
	}

	log.Printf("%s is on %s filesystem %q (%s)", path,
		ctx.Mount.Filesystem, ctx.Mount.Path, ctx.Mount.Device)
	return
}

// NewContextFromMountpoint makes a context for the filesystem at the specified
// mountpoint and whose Config is loaded from the global config file. On
// success, the Context contains a valid Config and Mount.
func NewContextFromMountpoint(mountpoint string) (ctx *Context, err error) {
	ctx = new(Context)

	if ctx.Mount, err = filesystem.GetMount(mountpoint); err != nil {
		err = util.UnderlyingError(err)
		return
	}

	if ctx.Config, err = getConfig(); err != nil {
		return
	}

	log.Printf("found %s filesystem %q (%s)", ctx.Mount.Filesystem,
		ctx.Mount.Path, ctx.Mount.Device)
	return
}

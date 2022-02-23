/*
 * protector.go - Functions for creating and getting action.Protectors which
 * ensure that login passphrases are on the correct filesystem.
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
	"os/user"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/util"
)

// createProtector makes a new protector on either ctx.Mount or if the requested
// source is a pam_passphrase, creates it on the root filesystem. Prompts for
// user input are used to get the source, name and keys.
func createProtectorFromContext(ctx *actions.Context) (*actions.Protector, error) {
	if err := promptForSource(ctx); err != nil {
		return nil, err
	}
	log.Printf("using source: %s", ctx.Config.Source.String())
	if ctx.Config.Source == metadata.SourceType_pam_passphrase {
		if userFlag.Value == "" && util.IsUserRoot() {
			return nil, ErrSpecifyUser
		}
		if !quietFlag.Value {
			fmt.Print(`
IMPORTANT: Before continuing, ensure you have properly set up your system for
           login protectors.  See
           https://github.com/google/fscrypt#setting-up-for-login-protectors

`)
		}
	}

	name, err := promptForName(ctx)
	if err != nil {
		return nil, err
	}
	log.Printf("using name: %s", name)

	// We only want to create new login protectors on the root filesystem.
	// So we make a new context if necessary.
	if ctx.Config.Source == metadata.SourceType_pam_passphrase &&
		ctx.Mount.Path != actions.LoginProtectorMountpoint {
		log.Printf("creating login protector on %q instead of %q",
			actions.LoginProtectorMountpoint, ctx.Mount.Path)
		if ctx, err = modifiedContext(ctx); err != nil {
			return nil, err
		}
	}

	var owner *user.User
	if ctx.Config.Source == metadata.SourceType_pam_passphrase && util.IsUserRoot() {
		owner = ctx.TargetUser
	}
	return actions.CreateProtector(ctx, name, createKeyFn, owner)
}

// selectExistingProtector returns a locked Protector which corresponds to an
// option in the non-empty slice of options. Prompts for user input are used to
// get the keys and select the option.
func selectExistingProtector(ctx *actions.Context, options []*actions.ProtectorOption) (*actions.Protector, error) {
	idx, err := promptForProtector(options)
	if err != nil {
		return nil, err
	}
	option := options[idx]

	log.Printf("using %s", formatInfo(option.ProtectorInfo))
	return actions.GetProtectorFromOption(ctx, option)
}

// expandedProtectorOptions gets all the actions.ProtectorOptions for ctx.Mount
// as well as any pam_passphrase protectors for the root filesystem.
func expandedProtectorOptions(ctx *actions.Context) ([]*actions.ProtectorOption, error) {
	options, err := ctx.ProtectorOptions()
	if err != nil {
		return nil, err
	}

	// Do nothing different if we are at the root, or cannot load the root.
	if ctx.Mount.Path == actions.LoginProtectorMountpoint {
		return options, nil
	}
	if ctx, err = modifiedContext(ctx); err != nil {
		log.Print(err)
		return options, nil
	}
	rootOptions, err := ctx.ProtectorOptions()
	if err != nil {
		log.Print(err)
		return options, nil
	}
	log.Print("adding additional ProtectorOptions")

	// Keep track of what we have seen, so we don't have duplicates
	seenOptions := make(map[string]bool)
	for _, option := range options {
		seenOptions[option.Descriptor()] = true
	}

	for _, option := range rootOptions {
		// Add in unseen passphrase protectors on the root filesystem
		// to the options list as potential linked protectors.
		if option.Source() == metadata.SourceType_pam_passphrase &&
			!seenOptions[option.Descriptor()] {
			option.LinkedMount = ctx.Mount
			options = append(options, option)
		}
	}

	return options, nil
}

// modifiedContext returns a copy of ctx with the mountpoint replaced by
// LoginProtectorMountpoint.
func modifiedContext(ctx *actions.Context) (*actions.Context, error) {
	mnt, err := filesystem.GetMount(actions.LoginProtectorMountpoint)
	if err != nil {
		return nil, err
	}

	modifiedCtx := *ctx
	modifiedCtx.Mount = mnt
	return &modifiedCtx, nil
}

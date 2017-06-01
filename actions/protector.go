/*
 * protector.go - functions for dealing with protectors
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

package actions

import (
	"errors"
	"os"

	"fscrypt/crypto"
	"fscrypt/metadata"
)

// Errors relating to Protectors
var (
	ErrProtectorName        = errors.New("login protectors do not need a name")
	ErrMissingProtectorName = errors.New("custom protectors must have a name")
	ErrDuplicateName        = errors.New("a protector with this name already exists")
	ErrDuplicateUID         = errors.New("there is already a login protector for this user")
)

// checkForProtectorWithName returns an error if there is already a protector
// on the filesystem with a specific name (or if we cannot read the necessary
// data).
func checkForProtectorWithName(ctx *Context, name string) error {
	options, err := ctx.ListProtectorOptions()
	if err != nil {
		return err
	}
	for _, option := range options {
		if option.Name() == name {
			return ErrDuplicateName
		}
	}
	return nil
}

// checkForProtectorWithUid returns an error if there is already a login
// protector on the filesystem with a specific UID (or if we cannot read the
// necessary data).
func checkForProtectorWithUID(ctx *Context, uid int64) error {
	options, err := ctx.ListProtectorOptions()
	if err != nil {
		return err
	}
	for _, option := range options {
		if option.Source() == metadata.SourceType_pam_passphrase && option.UID() == uid {
			return ErrDuplicateUID
		}
	}
	return nil
}

// Protector represents an unlocked protector, so it contains the ProtectorData
// as well as the actual protector key. These unlocked Protectors are necessary
// to unlock policies and create new polices. As with the key struct, a
// Protector should be wiped after use.
type Protector struct {
	Context *Context
	data    *metadata.ProtectorData
	key     *crypto.Key
}

// CreateProtector creates a protector with a given name (only for custom and
// raw protector types). The keyFn provided to create the Protector key will
// only be called once. If an error is returned, no data has been changed on the
// filesystem.
func CreateProtector(ctx *Context, name string, keyFn KeyFunc) (*Protector, error) {
	if err := ctx.checkContext(); err != nil {
		return nil, err
	}
	// Sanity checks for names
	if ctx.Config.Source == metadata.SourceType_pam_passphrase {
		// login protectors don't need a name (we use the username instead)
		if name != "" {
			return nil, ErrProtectorName
		}
	} else {
		// non-login protectors need a name (so we can distinguish between them)
		if name == "" {
			return nil, ErrMissingProtectorName
		}
		// we don't want to duplicate naming
		if err := checkForProtectorWithName(ctx, name); err != nil {
			return nil, err
		}
	}

	var err error
	protector := &Protector{
		Context: ctx,
		data: &metadata.ProtectorData{
			Name:   name,
			Source: ctx.Config.Source,
		},
	}

	// Extra data is needed for some SourceTypes
	switch protector.data.Source {
	case metadata.SourceType_pam_passphrase:
		// As the pam passphrases are user specific, we also store the
		// UID for this kind of source.
		protector.data.Uid = int64(os.Getuid())
		// Make sure we aren't duplicating protectors
		if err := checkForProtectorWithUID(ctx, protector.data.Uid); err != nil {
			return nil, err
		}
		fallthrough
	case metadata.SourceType_custom_passphrase:
		// Our passphrase sources need costs and a random salt.
		if protector.data.Salt, err = crypto.NewRandomBuffer(metadata.SaltLen); err != nil {
			return nil, err
		}

		protector.data.Costs = ctx.Config.HashCosts
	}

	// Randomly create the underlying protector key (and wipe if we fail)
	if protector.key, err = crypto.NewRandomKey(metadata.InternalKeyLen); err != nil {
		return nil, err
	}
	protector.data.ProtectorDescriptor = crypto.ComputeDescriptor(protector.key)

	if err := protector.Rewrap(keyFn); err != nil {
		protector.Wipe()
		return nil, err
	}

	return protector, nil
}

// GetProtector retrieves a Protector with a specific descriptor. The keyFn
// provided to unwrap the Protector key will be retied as necessary to get the
// correct key.
func GetProtector(ctx *Context, descriptor string, keyFn KeyFunc) (*Protector, error) {
	if err := ctx.checkContext(); err != nil {
		return nil, err
	}
	var err error
	protector := &Protector{Context: ctx}

	if protector.data, err = ctx.Mount.GetRegularProtector(descriptor); err != nil {
		return nil, err
	}

	protector.key, err = unwrapProtectorKey(ProtectorInfo{protector.data}, keyFn)
	return protector, err
}

// GetProtectorFromOption retrieves a protector based on a protector option.
// If the option had a load error, this function returns that error. The
// keyFn provided to unwrap the Protector key will be retied as necessary to
// get the correct key.
func GetProtectorFromOption(ctx *Context, option *ProtectorOption, keyFn KeyFunc) (*Protector, error) {
	if err := ctx.checkContext(); err != nil {
		return nil, err
	}
	if option.LoadError != nil {
		return nil, option.LoadError
	}

	// Replace the context if this is a linked protector
	if option.LinkedMount != nil {
		ctx = &Context{ctx.Config, option.LinkedMount}
	}
	var err error
	protector := &Protector{Context: ctx, data: option.data}

	protector.key, err = unwrapProtectorKey(option.ProtectorInfo, keyFn)
	return protector, err
}

// Rewrap updates the data that is wrapping the Protector Key. This is useful if
// a user's password has changed, for example. The keyFn provided to rewrap
// the Protector key will only be called once. If an error is returned, no data
// has been changed on the filesystem.
func (protector *Protector) Rewrap(keyFn KeyFunc) error {
	wrappingKey, err := getWrappingKey(ProtectorInfo{protector.data}, keyFn, false)
	if err != nil {
		return err
	}

	// Revert change to wrapped key on failure
	oldWrappedKey := protector.data.WrappedKey
	defer func() {
		wrappingKey.Wipe()
		if err != nil {
			protector.data.WrappedKey = oldWrappedKey
		}
	}()

	if protector.data.WrappedKey, err = crypto.Wrap(wrappingKey, protector.key); err != nil {
		return err
	}

	return protector.Context.Mount.AddProtector(protector.data)
}

// Wipe wipes a Protector's internal Key. It should always be called after using
// a Protector. This is often done with a defer statement.
func (protector *Protector) Wipe() error {
	return protector.key.Wipe()
}

// Destroy removes a protector from the filesystem. The internal key should
// still be wiped with Wipe().
func (protector *Protector) Destroy() error {
	return protector.Context.Mount.RemoveProtector(protector.data.ProtectorDescriptor)
}

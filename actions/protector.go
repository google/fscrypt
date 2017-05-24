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

// ListProtectorData creates a slice of all the data for Protectors on the
// Context's mountpoint.
func (ctx *Context) ListProtectorData() ([]ProtectorData, error) {
	descriptors, err := ctx.Mount.ListProtectors()
	if err != nil {
		return nil, err
	}

	data := make([]ProtectorData, len(descriptors))
	for i, descriptor := range descriptors {
		data[i], err = ctx.Mount.GetRegularProtector(descriptor)
		if err != nil {
			return nil, err
		}
	}
	return data, err
}

// checkForProtectorWithName returns an error if there is already a protector
// on the filesystem with a specific name (or if we cannot read the necessary
// data).
func (ctx *Context) checkForProtectorWithName(name string) error {
	protectors, err := ctx.ListProtectorData()
	if err != nil {
		return err
	}
	for _, protector := range protectors {
		if protector.GetName() == name {
			return ErrDuplicateName
		}
	}
	return nil
}

// checkForProtectorWithUid returns an error if there is already a login
// protector on the filesystem with a specific UID (or if we cannot read the
// necessary data).
func (ctx *Context) checkForProtectorWithUID(uid int64) error {
	protectors, err := ctx.ListProtectorData()
	if err != nil {
		return err
	}
	for _, protector := range protectors {
		if protector.GetSource() == metadata.SourceType_pam_passphrase &&
			protector.GetUid() == uid {
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
	*Context
	data *metadata.ProtectorData
	key  *crypto.Key
}

// NewProtector creates a protector with a given name (only for custom and raw
// protector types) and uses the provided KeyCallback to get the Key. The
// appropriate data is then stored on the filesystem. On error, nothing is
// changed on the filesystem.
func (ctx *Context) NewProtector(name string, callback KeyCallback) (*Protector, error) {
	if !ctx.Config.IsValid() {
		return nil, ErrBadConfig
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
		if err := ctx.checkForProtectorWithName(name); err != nil {
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
		if err := ctx.checkForProtectorWithUID(protector.data.Uid); err != nil {
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

	if err := protector.Rewrap(callback); err != nil {
		protector.Wipe()
		return nil, err
	}

	return protector, nil
}

// GetProtector retrieves a protector with a specific descriptor. As a key is
// necessary to unlock this Protector, a KeyCallback must also be provided.
func (ctx *Context) GetProtector(descriptor string, callback KeyCallback) (*Protector, error) {
	if !ctx.Config.IsValid() {
		return nil, ErrBadConfig
	}

	var err error
	protector := &Protector{Context: ctx}

	if protector.data, err = ctx.Mount.GetRegularProtector(descriptor); err != nil {
		return nil, err
	}

	protector.key, err = unwrapProtectorKey(protector.data, callback)
	return protector, err
}

// Rewrap updates the data that is wrapping the Protector Key. This is useful if
// a user's password has changed, for example. As a key is necessary to rewrap
// this Protector, a KeyCallback must be provided. If an error is returned, no
// data has been changed.
func (protector *Protector) Rewrap(callback KeyCallback) error {
	wrappingKey, err := getWrappingKey(protector.data, callback)
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

	return protector.Mount.AddProtector(protector.data)
}

// Wipe wipes a Protector's internal Key
func (protector *Protector) Wipe() error {
	return protector.key.Wipe()
}

// Destroy removes a protector from the filesystem. The internal key should
// still be wiped with Wipe().
func (protector *Protector) Destroy() error {
	return protector.Mount.RemoveProtector(protector.data.ProtectorDescriptor)
}

/*
 * protector.go - functions for dealing with policies
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
	"log"
	"reflect"

	"fscrypt/crypto"
	"fscrypt/filesystem"
	"fscrypt/metadata"
	"fscrypt/util"
)

// Errors relating to Policies
var (
	ErrBadPolicyMetadata   = util.SystemError("policy metadata is inconsistent")
	ErrPathWrongFilesystem = errors.New("provided path for policy is on the wrong filesystem")
	ErrDifferentFilesystem = errors.New("policies may only protect files on the same filesystem")
	ErrOnlyProtector       = errors.New("cannot remove the only protector for a policy")
	ErrAlreadyProtected    = errors.New("this policy is already protected by this protector")
	ErrNotProtected        = errors.New("this policy is not protected by this protector")
	ErrInvalidIndex        = errors.New("policy callback returned an invalid index")
)

// Policy represents an unlocked policy, so it contains the PolicyData as well
// as the actual protector key. These unlocked Polices can then be applied to a
// directory, or have their key material inserted into the keyring (which will
// allow encrypted files to be accessed). As with the key struct, a Policy
// should be wiped after use.
type Policy struct {
	*Context
	data *metadata.PolicyData
	key  *crypto.Key
}

// NewPolicy creates a Policy protected by given Protector and stores the
// appropriate data on the filesystem. On error, no data is changed on the
// filesystem.
func (ctx *Context) NewPolicy(protector *Protector) (*Policy, error) {
	if !ctx.Config.IsValid() {
		return nil, ErrBadConfig
	}

	// Randomly create the underlying policy key (and wipe if we fail)
	key, err := crypto.NewRandomKey(metadata.PolicyKeyLen)
	if err != nil {
		return nil, err
	}

	policy := &Policy{
		Context: ctx,
		data: &metadata.PolicyData{
			Options:       ctx.Config.Options,
			KeyDescriptor: crypto.ComputeDescriptor(key),
		},
		key: key,
	}

	if err = policy.AddProtector(protector); err != nil {
		policy.Wipe()
		return nil, err
	}

	return policy, nil
}

// getPolicyData creates a partially constructed policy by looking up
// the descriptor on the appropriate filesystem. The policy returned will not
// have its key initialized.
func (ctx *Context) getPolicyData(descriptor string) (*Policy, error) {
	data, err := ctx.Mount.GetPolicy(descriptor)
	if err != nil {
		return nil, err
	}
	log.Printf("got data for %s from filesystem", descriptor)

	return &Policy{Context: ctx, data: data}, nil
}

// GetPolicyFromDescriptor retrieves a policy with a specific descriptor. As a
// Protector is needed to unlock the policy, callbacks are necessary as well.
func (ctx *Context) GetPolicyFromDescriptor(descriptor string, c1 PolicyCallback, c2 KeyCallback) (*Policy, error) {
	if !ctx.Config.IsValid() {
		return nil, ErrBadConfig
	}

	policy, err := ctx.getPolicyData(descriptor)
	if err != nil {
		return nil, err
	}

	return policy, policy.unwrapPolicy(c1, c2)
}

// GetPolicyFromPath returns the policy for a specific path on the same
// filesystem as the Context. As a Protector is needed to unlock the policy,
// callbacks are necessary as well.
func (ctx *Context) GetPolicyFromPath(path string, c1 PolicyCallback, c2 KeyCallback) (*Policy, error) {
	if !ctx.Config.IsValid() {
		return nil, ErrBadConfig
	}

	// Policies and their paths will always be on the same filesystem
	if pathMount, err := filesystem.FindMount(path); err != nil {
		return nil, err
	} else if pathMount != ctx.Mount {
		return nil, ErrPathWrongFilesystem
	}
	log.Printf("using mountpoint %q for %q", ctx.Mount.Path, path)

	// We double check that the options agree for both the data we get from
	// the path, and the data we get from the mountpoint.
	pathData, err := metadata.GetPolicy(path)
	if err != nil {
		return nil, err
	}
	log.Printf("found policy %s for %s", pathData.KeyDescriptor, path)

	policy, err := ctx.getPolicyData(pathData.KeyDescriptor)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(pathData.Options, policy.data.Options) {
		log.Printf("options from path: %+v", pathData.Options)
		log.Printf("options from mountpoint: %+v", policy.data.Options)
		return nil, ErrBadPolicyMetadata
	}
	log.Print("data from filesystem and directory agree")

	return policy, policy.unwrapPolicy(c1, c2)
}

// unwrapPolicy initializes the policy key using the provided callbacks.
// The policyCallback
func (policy *Policy) unwrapPolicy(policyCallback PolicyCallback, keyCallback KeyCallback) error {
	// Create a list of the ProtectorData structures and a corresponding
	// list of the wrapped keys.
	totalKeys := len(policy.data.WrappedPolicyKeys)
	protectors := make([]ProtectorData, 0, totalKeys)
	wrappedKeys := make([]*metadata.WrappedKeyData, 0, totalKeys)

	// This loop excludes protectors that we cannot get from the mount.
	for _, wrappedPolicyKey := range policy.data.WrappedPolicyKeys {
		protector, err := policy.Mount.GetEitherProtector(wrappedPolicyKey.ProtectorDescriptor)
		if err != nil {
			log.Print(err)
			continue
		}
		protectors = append(protectors, protector)
		wrappedKeys = append(wrappedKeys, wrappedPolicyKey.WrappedKey)
	}
	log.Printf("%d of our %d protectors are available", len(protectors), totalKeys)

	idx, err := policyCallback(policy.data.KeyDescriptor, protectors)
	if err != nil {
		return err
	}
	if idx < 0 || idx >= len(protectors) {
		return ErrInvalidIndex
	}

	protectorData := protectors[idx].(*metadata.ProtectorData)
	wrappedPolicyKey := wrappedKeys[idx]
	log.Printf("protector %s selected in callback", protectorData.ProtectorDescriptor)

	protectorKey, err := unwrapProtectorKey(protectorData, keyCallback)
	if err != nil {
		return err
	}
	defer protectorKey.Wipe()

	log.Printf("unwrapping policy %s with protector", policy.data.KeyDescriptor)
	policy.key, err = crypto.Unwrap(protectorKey, wrappedPolicyKey)
	return err
}

// AddProtector updates the data that is wrapping the Policy Key so that the
// provided Protector is now protecting the specified Policy. If an error is
// returned, no data has been changed. If the policy and protector are on
// different filesystems, a link will be created between them.
func (policy *Policy) AddProtector(protector *Protector) error {
	_, err := policy.findWrappedKeyIndex(protector)
	if err == nil {
		return ErrAlreadyProtected
	}

	// If the protector is on a different filesystem, we need to add a link
	// to it on the policy's filesystem.
	if policy.Mount != protector.Mount {
		err = policy.Mount.AddLinkedProtector(
			protector.data.ProtectorDescriptor, protector.Mount)
		if err != nil {
			return err
		}
	}

	// Create the wrapped policy key
	wrappedPolicyKey := &metadata.WrappedPolicyKey{
		ProtectorDescriptor: protector.data.ProtectorDescriptor,
	}

	if wrappedPolicyKey.WrappedKey, err = crypto.Wrap(protector.key, policy.key); err != nil {
		return err
	}

	// Append the wrapped key to the data
	policy.addKey(wrappedPolicyKey)

	if err = policy.commitData(); err != nil {
		// revert the addition on failure
		policy.removeKey(len(policy.data.WrappedPolicyKeys) - 1)
		return err
	}
	return nil
}

// RemoveProtector updates the data that is wrapping the Policy Key so that the
// provided Protector is no longer protecting the specified Policy. If an error
// is returned, no data has been changed. Note that w do not attempt to remove
// any links (for the case where the protector and policy are on different
// filesystems). This is because one protector may protect many polices.
func (policy *Policy) RemoveProtector(protector *Protector) error {
	idx, err := policy.findWrappedKeyIndex(protector)
	if err != nil {
		return err
	}

	if len(policy.data.WrappedPolicyKeys) == 1 {
		return ErrOnlyProtector
	}

	// Remove the wrapped key from the data
	toRemove := policy.removeKey(idx)

	if err = policy.commitData(); err != nil {
		// revert the removal on failure (order is irrelevant)
		policy.addKey(toRemove)
		return err
	}
	return nil
}

// Apply sets the Policy on a specified directory. Currently we impose the
// additional constraint that policies and the directories they are applied to
// must reside on the same filesystem.
func (policy *Policy) Apply(path string) error {
	if pathMount, err := filesystem.FindMount(path); err != nil {
		return err
	} else if pathMount != policy.Mount {
		return ErrDifferentFilesystem
	}

	return metadata.SetPolicy(path, policy.data)
}

// Unlock provisions the Policy key into the kernel keyring. This allows reading
// and writing of files encrypted with this directory.
func (policy *Policy) Unlock() error {
	service := crypto.ServiceDefault

	// For legacy configurations, we may need non-standard services
	if policy.Config.HasCompatibilityOption(LegacyConfig) {
		switch policy.Mount.Filesystem {
		case "ext4":
			service = crypto.ServiceExt4
		case "f2fs":
			service = crypto.ServiceF2FS
		}
	}

	return crypto.InsertPolicyKey(policy.key, policy.data.KeyDescriptor, service)
}

// Wipe wipes a Policy's internal Key.
func (policy *Policy) Wipe() error {
	return policy.key.Wipe()
}

// Destroy removes a policy from the filesystem. The internal key should still
// be wiped with Wipe().
func (policy *Policy) Destroy() error {
	return policy.Mount.RemovePolicy(policy.data.KeyDescriptor)
}

// commitData writes the Policy's current data to the filesystem
func (policy *Policy) commitData() error {
	return policy.Mount.AddPolicy(policy.data)
}

// findWrappedPolicyKey returns the index of the wrapped policy key
// corresponding to this policy and protector. An error is returned if no
// wrapped policy key corresponds to the specified protector.
func (policy *Policy) findWrappedKeyIndex(protector *Protector) (int, error) {
	for idx, wrappedPolicyKey := range policy.data.WrappedPolicyKeys {
		if wrappedPolicyKey.ProtectorDescriptor == protector.data.ProtectorDescriptor {
			return idx, nil
		}
	}

	return 0, ErrNotProtected
}

// addKey adds the wrapped policy key to end of the wrapped key data.
func (policy *Policy) addKey(toAdd *metadata.WrappedPolicyKey) {
	policy.data.WrappedPolicyKeys = append(policy.data.WrappedPolicyKeys, toAdd)
}

// remove removes the wrapped policy key at the specified index. This
// does not preserve the order of the wrapped policy key array. If no index is
// specified the last key is removed.
func (policy *Policy) removeKey(index int) *metadata.WrappedPolicyKey {
	lastIdx := len(policy.data.WrappedPolicyKeys) - 1
	toRemove := policy.data.WrappedPolicyKeys[index]

	// See https://github.com/golang/go/wiki/SliceTricks
	policy.data.WrappedPolicyKeys[index] = policy.data.WrappedPolicyKeys[lastIdx]
	policy.data.WrappedPolicyKeys[lastIdx] = nil
	policy.data.WrappedPolicyKeys = policy.data.WrappedPolicyKeys[:lastIdx]

	return toRemove
}

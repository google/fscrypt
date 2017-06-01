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
	ErrMissingPolicyMetadata  = util.SystemError("policy for directory has no filesystem metadata; metadata may be corrupted")
	ErrPolicyMetadataMismatch = util.SystemError("policy metadata is inconsistent; metadata may be corrupted")
	ErrPathWrongFilesystem    = errors.New("provided path for policy is on the wrong filesystem")
	ErrDifferentFilesystem    = errors.New("policies may only protect files on the same filesystem")
	ErrOnlyProtector          = errors.New("cannot remove the only protector for a policy")
	ErrAlreadyProtected       = errors.New("this policy is already protected by this protector")
	ErrNotProtected           = errors.New("this policy is not protected by this protector")
)

// PolicyDescriptorForPath returns the policy descriptor for a file on the
// filesystem. An error is returned if the metadata is inconsistent, the path is
// for the wrong filesystem, or the path is not encrypted.
func PolicyDescriptorForPath(ctx *Context, path string) (string, error) {
	if err := ctx.checkContext(); err != nil {
		return "", err
	}
	// Policies and their paths will always be on the same filesystem
	if pathMount, err := filesystem.FindMount(path); err != nil {
		return "", err
	} else if pathMount != ctx.Mount {
		return "", ErrPathWrongFilesystem
	}
	log.Printf("%q is on mountpoint %q", path, ctx.Mount.Path)

	// We double check that the options agree for both the data we get from
	// the path, and the data we get from the mountpoint.
	pathData, err := metadata.GetPolicy(path)
	if err != nil {
		return "", err
	}
	descriptor := pathData.KeyDescriptor
	log.Printf("found policy %s for %q", descriptor, path)

	mountData, err := ctx.Mount.GetPolicy(descriptor)
	if err != nil {
		log.Printf("getting metadata for policy %s: %v", descriptor, err)
		return "", ErrMissingPolicyMetadata
	}
	log.Printf("found data for policy %s on %q", descriptor, ctx.Mount.Path)

	if !reflect.DeepEqual(pathData.Options, mountData.Options) {
		log.Printf("options from path: %+v", pathData.Options)
		log.Printf("options from mount: %+v", mountData.Options)
		return "", ErrPolicyMetadataMismatch
	}
	log.Print("data from filesystem and path agree")

	return descriptor, nil
}

// IsPolicyUnlocked returns a boolean indicating if the corresponding policy for
// this filesystem has its key in the keyring, meaning files and directories
// using this policy can be read and written.
func IsPolicyUnlocked(ctx *Context, policyDescriptor string) bool {
	_, err := crypto.FindPolicyKey(policyDescriptor, getService(ctx))
	return err == nil
}

// LockPolicy removes a policy key from the keyring. This means after unmounting
// and remounting the directory, files and directories using this policy will be
// inaccessible.
func LockPolicy(ctx *Context, policyDescriptor string) error {
	if err := ctx.checkContext(); err != nil {
		return err
	}
	return crypto.RemovePolicyKey(policyDescriptor, getService(ctx))
}

// PurgeAllPolicies removes all policy keys on the filesystem from the kernel
// keyring. In order for this removal to have an effect, the filesystem should
// also be unmounted.
func PurgeAllPolicies(ctx *Context) error {
	if err := ctx.checkContext(); err != nil {
		return err
	}
	policies, err := ctx.Mount.ListPolicies()
	if err != nil {
		return err
	}

	for _, policy := range policies {
		if err := LockPolicy(ctx, policy); err == crypto.ErrKeyringDelete {
			// This means a policy key was present but we could not
			// delete it. The other errors just indicate that the
			// policy key was not present.
			return err
		}
	}
	return nil
}

// getService returns the keyring service for this context. We use the presence
// of the LegacyConfig flag to determine if we should use the legacy services
// (which are necessary for kernels before v4.8).
func getService(ctx *Context) string {
	if ctx.Config.HasCompatibilityOption(LegacyConfig) {
		switch ctx.Mount.Filesystem {
		case "ext4", "f2fs":
			return ctx.Mount.Filesystem + ":"
		}
	}
	return crypto.DefaultService
}

// getPolicyData creates a partially constructed policy by looking up
// the descriptor on the appropriate filesystem. The policy returned will not
// have its key initialized.
func getPolicyData(ctx *Context, descriptor string) (*Policy, error) {
	if err := ctx.checkContext(); err != nil {
		return nil, err
	}
	data, err := ctx.Mount.GetPolicy(descriptor)
	if err != nil {
		return nil, err
	}
	log.Printf("got data for %s from %q", descriptor, ctx.Mount.Path)

	return &Policy{Context: ctx, data: data}, nil
}

// Policy represents an unlocked policy, so it contains the PolicyData as well
// as the actual protector key. These unlocked Polices can then be applied to a
// directory, or have their key material inserted into the keyring (which will
// allow encrypted files to be accessed). As with the key struct, a Policy
// should be wiped after use.
type Policy struct {
	Context *Context
	data    *metadata.PolicyData
	key     *crypto.Key
}

// CreatePolicy creates a Policy protected by given Protector and stores the
// appropriate data on the filesystem. On error, no data is changed on the
// filesystem.
func CreatePolicy(ctx *Context, protector *Protector) (*Policy, error) {
	if err := ctx.checkContext(); err != nil {
		return nil, err
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

// GetPolicy retrieves a policy with a specific descriptor. As a Protector is
// needed to unlock the policy, callbacks to select the policy and get the key
// are needed. This method will retry the keyFn as necessary to get the correct
// key for the selected protector.
func GetPolicy(ctx *Context, descriptor string, optionFn OptionFunc, keyFn KeyFunc) (*Policy, error) {
	policy, err := getPolicyData(ctx, descriptor)
	if err != nil {
		return nil, err
	}
	return policy, policy.unwrapPolicy(optionFn, keyFn)
}

// listOptions creates a slice of ProtectorOptions for the protectors protecting
// this policy.
func (policy *Policy) listOptions() []*ProtectorOption {
	options := make([]*ProtectorOption, len(policy.data.WrappedPolicyKeys))
	for i, wrappedPolicyKey := range policy.data.WrappedPolicyKeys {
		options[i] = policy.Context.GetProtectorOption(wrappedPolicyKey.ProtectorDescriptor)
	}
	return options
}

// unwrapPolicy initializes the policy key using the provided callbacks.
func (policy *Policy) unwrapPolicy(optionFn OptionFunc, keyFn KeyFunc) error {
	// Create a list of the ProtectorOptions and a list of the wrapped keys.
	options := policy.listOptions()
	wrappedKeys := make([]*metadata.WrappedKeyData, len(policy.data.WrappedPolicyKeys))

	for i, wrappedPolicyKey := range policy.data.WrappedPolicyKeys {
		wrappedKeys[i] = wrappedPolicyKey.WrappedKey
	}

	// The OptionFunc indicates which option and wrapped key we should use.
	idx, err := optionFn(policy.data.KeyDescriptor, options)
	if err != nil {
		return err
	}
	option := options[idx]
	if option.LoadError != nil {
		return option.LoadError
	}

	wrappedPolicyKey := wrappedKeys[idx]
	log.Printf("protector %s selected in callback", option.Descriptor())

	protectorKey, err := unwrapProtectorKey(option.ProtectorInfo, keyFn)
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
	_, err := policy.findWrappedKeyIndex(protector.data.ProtectorDescriptor)
	if err == nil {
		return ErrAlreadyProtected
	}

	// If the protector is on a different filesystem, we need to add a link
	// to it on the policy's filesystem.
	if policy.Context.Mount != protector.Context.Mount {
		err = policy.Context.Mount.AddLinkedProtector(
			protector.data.ProtectorDescriptor, protector.Context.Mount)
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
func (policy *Policy) RemoveProtector(protectorDescriptor string) error {
	idx, err := policy.findWrappedKeyIndex(protectorDescriptor)
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
	} else if pathMount != policy.Context.Mount {
		return ErrDifferentFilesystem
	}

	return metadata.SetPolicy(path, policy.data)
}

// Unlock provisions the Policy key into the kernel keyring. This allows reading
// and writing of files encrypted with this directory.
func (policy *Policy) Unlock() error {
	return crypto.InsertPolicyKey(policy.key, policy.data.KeyDescriptor, getService(policy.Context))
}

// Wipe wipes a Policy's internal Key. It should always be called after using a
// Policy. This is often done with a defer statement.
func (policy *Policy) Wipe() error {
	return policy.key.Wipe()
}

// Destroy removes a policy from the filesystem. The internal key should still
// be wiped with Wipe().
func (policy *Policy) Destroy() error {
	return policy.Context.Mount.RemovePolicy(policy.data.KeyDescriptor)
}

// commitData writes the Policy's current data to the filesystem
func (policy *Policy) commitData() error {
	return policy.Context.Mount.AddPolicy(policy.data)
}

// findWrappedPolicyKey returns the index of the wrapped policy key
// corresponding to this policy and protector. An error is returned if no
// wrapped policy key corresponds to the specified protector.
func (policy *Policy) findWrappedKeyIndex(protectorDescriptor string) (int, error) {
	for idx, wrappedPolicyKey := range policy.data.WrappedPolicyKeys {
		if wrappedPolicyKey.ProtectorDescriptor == protectorDescriptor {
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

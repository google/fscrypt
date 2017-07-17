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
	"fmt"
	"log"
	"reflect"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/util"
)

// Errors relating to Policies
var (
	ErrMissingPolicyMetadata  = util.SystemError("missing policy metadata for encrypted directory")
	ErrPolicyMetadataMismatch = util.SystemError("inconsistent metadata between filesystem and directory")
	ErrDifferentFilesystem    = errors.New("policies may only protect files on the same filesystem")
	ErrOnlyProtector          = errors.New("cannot remove the only protector for a policy")
	ErrAlreadyProtected       = errors.New("policy already protected by protector")
	ErrNotProtected           = errors.New("policy not protected by protector")
)

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

	for _, policyDescriptor := range policies {
		service := ctx.getService()
		err = crypto.RemovePolicyKey(service + policyDescriptor)

		switch errors.Cause(err) {
		case nil, crypto.ErrKeyringSearch:
			// We don't care if the key has already been removed
			break
		default:
			return err
		}
	}
	return nil
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
	created bool
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
		key:     key,
		created: true,
	}

	if err = policy.AddProtector(protector); err != nil {
		policy.Lock()
		return nil, err
	}

	return policy, nil
}

// GetPolicy retrieves a locked policy with a specific descriptor. The Policy is
// still locked in this case, so it must be unlocked before using certain
// methods.
func GetPolicy(ctx *Context, descriptor string) (*Policy, error) {
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

// GetPolicyFromPath returns the locked policy descriptor for a file on the
// filesystem. The Policy is still locked in this case, so it must be unlocked
// before using certain methods. An error is returned if the metadata is
// inconsistent or the path is not encrypted.
func GetPolicyFromPath(ctx *Context, path string) (*Policy, error) {
	if err := ctx.checkContext(); err != nil {
		return nil, err
	}

	// We double check that the options agree for both the data we get from
	// the path, and the data we get from the mountpoint.
	pathData, err := metadata.GetPolicy(path)
	if err != nil {
		return nil, err
	}
	descriptor := pathData.KeyDescriptor
	log.Printf("found policy %s for %q", descriptor, path)

	mountData, err := ctx.Mount.GetPolicy(descriptor)
	if err != nil {
		log.Printf("getting policy metadata: %v", err)
		return nil, errors.Wrap(ErrMissingPolicyMetadata, path)
	}
	log.Printf("found data for policy %s on %q", descriptor, ctx.Mount.Path)

	if !reflect.DeepEqual(pathData.Options, mountData.Options) {
		log.Printf("options from path: %+v", pathData.Options)
		log.Printf("options from mount: %+v", mountData.Options)
		return nil, errors.Wrapf(ErrPolicyMetadataMismatch, "policy %s", descriptor)
	}
	log.Print("data from filesystem and path agree")

	return &Policy{Context: ctx, data: mountData}, nil
}

// ProtectorOptions creates a slice of ProtectorOptions for the protectors
// protecting this policy.
func (policy *Policy) ProtectorOptions() []*ProtectorOption {
	options := make([]*ProtectorOption, len(policy.data.WrappedPolicyKeys))
	for i, wrappedPolicyKey := range policy.data.WrappedPolicyKeys {
		options[i] = policy.Context.getProtectorOption(wrappedPolicyKey.ProtectorDescriptor)
	}
	return options
}

// ProtectorDescriptors creates a slice of the Protector descriptors for the
// protectors protecting this policy.
func (policy *Policy) ProtectorDescriptors() []string {
	descriptors := make([]string, len(policy.data.WrappedPolicyKeys))
	for i, wrappedPolicyKey := range policy.data.WrappedPolicyKeys {
		descriptors[i] = wrappedPolicyKey.ProtectorDescriptor
	}
	return descriptors
}

// Descriptor returns the key descriptor for this policy.
func (policy *Policy) Descriptor() string {
	return policy.data.KeyDescriptor
}

// Description returns the description that will be used when the key for this
// Policy is inserted into the keyring
func (policy *Policy) Description() string {
	return policy.Context.getService() + policy.Descriptor()
}

// Destroy removes a policy from the filesystem. The internal key should still
// be wiped with Lock().
func (policy *Policy) Destroy() error {
	return policy.Context.Mount.RemovePolicy(policy.Descriptor())
}

// Revert destroys a policy if it was created, but does nothing if it was just
// queried from the filesystem.
func (policy *Policy) Revert() error {
	if !policy.created {
		return nil
	}
	return policy.Destroy()
}

func (policy *Policy) String() string {
	return fmt.Sprintf("Policy: %s\nMountpoint: %s\nOptions: %v\nProtectors:%+v",
		policy.Descriptor(), policy.Context.Mount, policy.data.Options,
		policy.ProtectorDescriptors())
}

// Unlock unwraps the Policy's internal key. As a Protector is needed to unlock
// the Policy, callbacks to select the Policy and get the key are needed. This
// method will retry the keyFn as necessary to get the correct key for the
// selected protector. Does nothing if policy is already unlocked.
func (policy *Policy) Unlock(optionFn OptionFunc, keyFn KeyFunc) error {
	if policy.key != nil {
		return nil
	}
	options := policy.ProtectorOptions()

	// The OptionFunc indicates which option and wrapped key we should use.
	idx, err := optionFn(policy.Descriptor(), options)
	if err != nil {
		return err
	}
	option := options[idx]
	if option.LoadError != nil {
		return option.LoadError
	}

	log.Printf("protector %s selected in callback", option.Descriptor())
	protectorKey, err := unwrapProtectorKey(option.ProtectorInfo, keyFn)
	if err != nil {
		return err
	}
	defer protectorKey.Wipe()

	log.Printf("unwrapping policy %s with protector", policy.Descriptor())
	wrappedPolicyKey := policy.data.WrappedPolicyKeys[idx].WrappedKey
	policy.key, err = crypto.Unwrap(protectorKey, wrappedPolicyKey)
	return err
}

// UnlockWithProtector uses an unlocked Protector to unlock a policy. An error
// is returned if the Protector is not yet unlocked or does not protect the
// policy. Does nothing if policy is already unlocked.
func (policy *Policy) UnlockWithProtector(protector *Protector) error {
	if policy.key != nil {
		return nil
	}
	if protector.key == nil {
		return ErrLocked
	}
	idx, ok := policy.findWrappedKeyIndex(protector.Descriptor())
	if !ok {
		return ErrNotProtected
	}

	var err error
	wrappedPolicyKey := policy.data.WrappedPolicyKeys[idx].WrappedKey
	policy.key, err = crypto.Unwrap(protector.key, wrappedPolicyKey)
	return err
}

// Lock wipes a Policy's internal Key. It should always be called after using a
// Policy. This is often done with a defer statement. There is no effect if
// called multiple times.
func (policy *Policy) Lock() error {
	err := policy.key.Wipe()
	policy.key = nil
	return err
}

// AddProtector updates the data that is wrapping the Policy Key so that the
// provided Protector is now protecting the specified Policy. If an error is
// returned, no data has been changed. If the policy and protector are on
// different filesystems, a link will be created between them. The policy and
// protector must both be unlocked.
func (policy *Policy) AddProtector(protector *Protector) error {
	if _, ok := policy.findWrappedKeyIndex(protector.Descriptor()); ok {
		return ErrAlreadyProtected
	}
	if policy.key == nil || protector.key == nil {
		return ErrLocked
	}

	// If the protector is on a different filesystem, we need to add a link
	// to it on the policy's filesystem.
	if policy.Context.Mount != protector.Context.Mount {
		log.Printf("policy on %s\n protector on %s\n", policy.Context.Mount, protector.Context.Mount)
		err := policy.Context.Mount.AddLinkedProtector(
			protector.Descriptor(), protector.Context.Mount)
		if err != nil {
			return err
		}
	} else {
		log.Printf("policy and protector both on %q", policy.Context.Mount)
	}

	// Create the wrapped policy key
	wrappedKey, err := crypto.Wrap(protector.key, policy.key)
	if err != nil {
		return err
	}

	// Append the wrapped key to the data
	policy.addKey(&metadata.WrappedPolicyKey{
		ProtectorDescriptor: protector.Descriptor(),
		WrappedKey:          wrappedKey,
	})

	if err := policy.commitData(); err != nil {
		// revert the addition on failure
		policy.removeKey(len(policy.data.WrappedPolicyKeys) - 1)
		return err
	}
	return nil
}

// RemoveProtector updates the data that is wrapping the Policy Key so that the
// provided Protector is no longer protecting the specified Policy. If an error
// is returned, no data has been changed. Note that no protector links are
// removed (in the case where the protector and policy are on different
// filesystems). The policy and protector can be locked or unlocked.
func (policy *Policy) RemoveProtector(protector *Protector) error {
	idx, ok := policy.findWrappedKeyIndex(protector.Descriptor())
	if !ok {
		return ErrNotProtected
	}

	if len(policy.data.WrappedPolicyKeys) == 1 {
		return ErrOnlyProtector
	}

	// Remove the wrapped key from the data
	toRemove := policy.removeKey(idx)

	if err := policy.commitData(); err != nil {
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

// IsProvisioned returns a boolean indicating if the policy has its key in the
// keyring, meaning files and directories using this policy are accessible.
func (policy *Policy) IsProvisioned() bool {
	_, _, err := crypto.FindPolicyKey(policy.Description())
	return err == nil
}

// Provision inserts the Policy key into the kernel keyring. This allows reading
// and writing of files encrypted with this directory. Requires unlocked Policy.
func (policy *Policy) Provision() error {
	if policy.key == nil {
		return ErrLocked
	}
	return crypto.InsertPolicyKey(policy.key, policy.Description())
}

// Deprovision removes the Policy key from the kernel keyring. This prevents
// reading and writing to the directory once the caches are cleared.
func (policy *Policy) Deprovision() error {
	return crypto.RemovePolicyKey(policy.Description())
}

// commitData writes the Policy's current data to the filesystem.
func (policy *Policy) commitData() error {
	return policy.Context.Mount.AddPolicy(policy.data)
}

// findWrappedPolicyKey returns the index of the wrapped policy key
// corresponding to this policy and protector. The returned bool is false if no
// wrapped policy key corresponds to the specified protector, true otherwise.
func (policy *Policy) findWrappedKeyIndex(protectorDescriptor string) (int, bool) {
	for idx, wrappedPolicyKey := range policy.data.WrappedPolicyKeys {
		if wrappedPolicyKey.ProtectorDescriptor == protectorDescriptor {
			return idx, true
		}
	}
	return 0, false
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

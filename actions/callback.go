/*
 * callback.go - defines how the caller of an action function passes along a key
 * to be used in this package.
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
	"fscrypt/crypto"
	"fscrypt/metadata"
	"log"
)

// ProtectorData is the information a caller will receive about a Protector
// before they have to return the corresponding key. This is currently a
// read-only view of metadata.ProtectorData.
type ProtectorData interface {
	GetProtectorDescriptor() string
	GetSource() metadata.SourceType
	GetName() string
	GetUid() int64
}

// KeyCallback is passed to a function that will require a key from the caller.
// For passphrase sources, the returned key should be a password. For raw
// sources, the returned key should be a standard cryptographic key. Consumers
// of the callback will wipe the provided key. If the callback returns an error,
// the function to which the callback is passed returns that error. Note that
// when using the key to unwrap a known key, the callback will be executed until
// the correct key is returned or an error is returned.
type KeyCallback func(data ProtectorData) (*crypto.Key, error)

// getWrappingKey uses the provided callback to get the wrapping key
// corresponding to the ProtectorData. This runs the passphrase hash for
// passphrase sources or just relays the callback for raw sources.
func getWrappingKey(data *metadata.ProtectorData, callback KeyCallback) (*crypto.Key, error) {
	// We don't need to go anything for raw keys
	if data.Source == metadata.SourceType_raw_key {
		return callback(data)
	}

	// Run the passphrase hash for other sources.
	passphrase, err := callback(data)
	if err != nil {
		return nil, err
	}
	defer passphrase.Wipe()

	log.Printf("running passphrase hash for protector %s", data.ProtectorDescriptor)
	return crypto.PassphraseHash(passphrase, data.Salt, data.Costs)
}

// unwrapProtectorKey uses the provided callback and protector data to return
// the unwrapped protector key. This will repeatedly use the callback to get the
// wrapping key until the correct key is returned or an error is returned.
func unwrapProtectorKey(data *metadata.ProtectorData, callback KeyCallback) (*crypto.Key, error) {
	for {
		wrappingKey, err := getWrappingKey(data, callback)
		if err != nil {
			return nil, err
		}

		protectorKey, err := crypto.Unwrap(wrappingKey, data.WrappedKey)
		wrappingKey.Wipe()
		switch err {
		case nil:
			log.Printf("valid wrapping key for protector %s", data.ProtectorDescriptor)
			return protectorKey, nil
		case crypto.ErrBadAuth:
			log.Printf("invalid wrapping key for protector %s", data.ProtectorDescriptor)
			continue
		default:
			return nil, err
		}
	}
}

// PolicyCallback is passed to a function that needs to unlock a policy. The
// callback is used so that the caller can specify which protector they wish to
// use to unlock a policy. The descriptor is the KeyDescriptor for the Policy,
// while for each Protector protecting the policy there is either an entry in
// protectors (if we were able to read the Protector's data). The PolicyCallback
// should either return a valid index into protectors corresponding to the
// desired protector, or an error. If the callback returns an error, the
// function to which the callback is passed returns that error.
type PolicyCallback func(descriptor string, protectors []ProtectorData) (int, error)

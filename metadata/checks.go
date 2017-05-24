/*
 * checks.go - Some sanity check methods for our metadata structures
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

package metadata

import (
	"log"

	"github.com/golang/protobuf/proto"

	"fscrypt/util"
)

// Metadata is the interface to all of the protobuf structures that can be
// checked with the IsValid method.
type Metadata interface {
	IsValid() bool
	proto.Message
}

// checkValidLength returns true if expected == actual, otherwise it logs an
// InvalidLengthError.
func checkValidLength(name string, expected int, actual int) bool {
	if expected != actual {
		log.Print(util.InvalidLengthError(name, expected, actual))
		return false
	}
	return true
}

// IsValid ensures the mode has a name and isn't empty.
func (m EncryptionOptions_Mode) IsValid() bool {
	if m.String() == "" {
		log.Print("Encryption mode cannot be the empty string")
		return false
	}
	if m == EncryptionOptions_default {
		log.Print("Encryption mode must be set to a non-default value")
		return false
	}
	return true
}

// IsValid ensures the source has a name and isn't empty.
func (s SourceType) IsValid() bool {
	if s.String() == "" {
		log.Print("SourceType cannot be the empty string")
		return false
	}
	if s == SourceType_default {
		log.Print("SourceType must be set to a non-default value")
		return false
	}
	return true
}

// IsValid ensures the hash costs will be accepted by Argon2.
func (h *HashingCosts) IsValid() bool {
	if h == nil {
		log.Print("HashingCosts not initialized")
		return false
	}
	if h.Time == 0 {
		log.Print("Hashing time cost not initialized")
		return false
	}
	if h.Parallelism == 0 {
		log.Print("Hashing parallelism cost not initialized")
		return false
	}
	minMemory := 8 * h.Parallelism
	if h.Memory < minMemory {
		log.Printf("Hashing memory cost must be at least %d", minMemory)
		return false
	}
	return true
}

// IsValid ensures our buffers are the correct length (or just exist).
func (w *WrappedKeyData) IsValid() bool {
	if w == nil {
		log.Print("WrappedKeyData not initialized")
		return false
	}
	if len(w.EncryptedKey) == 0 {
		log.Print("EncryptedKey not initialized")
		return false
	}
	return checkValidLength("IV", IVLen, len(w.IV)) &&
		checkValidLength("HMAC", HMACLen, len(w.Hmac))
}

// IsValid ensures our ProtectorData has the correct fields for its source.
func (p *ProtectorData) IsValid() bool {
	if p == nil {
		log.Print("ProtectorData not initialized")
		return false
	}

	// Source specific checks
	switch p.Source {
	case SourceType_pam_passphrase:
		if p.Uid < 0 {
			log.Print("The UID should never be negative")
			return false
		}
		fallthrough
	case SourceType_custom_passphrase:
		if !p.Costs.IsValid() || !checkValidLength("Salt", SaltLen, len(p.Salt)) {
			return false
		}
	}

	// Generic checks
	return p.Source.IsValid() &&
		p.WrappedKey.IsValid() &&
		checkValidLength("EncryptedKey", InternalKeyLen, len(p.WrappedKey.EncryptedKey)) &&
		checkValidLength("ProtectorDescriptor", DescriptorLen, len(p.ProtectorDescriptor))

}

// IsValid ensures each of the options is valid.
func (e *EncryptionOptions) IsValid() bool {
	if e == nil {
		log.Print("EncryptionOptions not initialized")
		return false
	}
	if _, ok := util.Index(e.Padding, paddingArray); !ok {
		log.Printf("Padding of %d is invalid", e.Padding)
		return false
	}

	return e.Contents.IsValid() && e.Filenames.IsValid()
}

// IsValid ensures the fields are valid and have the correct lengths.
func (w *WrappedPolicyKey) IsValid() bool {
	if w == nil {
		log.Print("WrappedPolicyKey not initialized")
		return false
	}
	return w.WrappedKey.IsValid() &&
		checkValidLength("EncryptedKey", PolicyKeyLen, len(w.WrappedKey.EncryptedKey)) &&
		checkValidLength("ProtectorDescriptor", DescriptorLen, len(w.ProtectorDescriptor))
}

// IsValid ensures the fields and each wrapped key are valid.
func (p *PolicyData) IsValid() bool {
	if p == nil {
		log.Print("PolicyData not initialized")
		return false
	}
	// Check each wrapped key
	for _, w := range p.WrappedPolicyKeys {
		if !w.IsValid() {
			return false
		}
	}
	return p.Options.IsValid() &&
		checkValidLength("KeyDescriptor", DescriptorLen, len(p.KeyDescriptor))
}

// IsValid ensures the Config has all the necessary info for its Source.
func (c *Config) IsValid() bool {
	// General checks
	if c == nil {
		log.Print("Config not initialized")
		return false
	}
	if !c.Source.IsValid() || !c.Options.IsValid() {
		return false
	}

	// Source specific checks
	switch c.Source {
	case SourceType_pam_passphrase, SourceType_custom_passphrase:
		return c.HashCosts.IsValid()
	default:
		return true
	}
}

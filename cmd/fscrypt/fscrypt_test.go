/*
 * fscrypt_test.go - Stub test file that has one test that always passes.
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
	"strings"
	"testing"
)

func TestTrivial(t *testing.T) {}

func TestMatchMetadataFlag(t *testing.T) {
	testCases := []struct {
		flagValue        string
		wantMountpoint   string
		wantDescriptor   string
		wantErrSubstring string
	}{
		{
			flagValue:      "/mnt/ext4:c198cb2e6ceb4a12",
			wantMountpoint: "/mnt/ext4",
			wantDescriptor: "c198cb2e6ceb4a12",
		},
		{
			// The mountpoint may contain non-ASCII characters.
			flagValue:      "/mnt/miroir-données:d77aa788ff9d1931",
			wantMountpoint: "/mnt/miroir-données",
			wantDescriptor: "d77aa788ff9d1931",
		},
		{
			flagValue:      "/mnt/naïve:abc123",
			wantMountpoint: "/mnt/naïve",
			wantDescriptor: "abc123",
		},
		{
			// Missing separator or descriptor is rejected.
			flagValue:        "abc",
			wantErrSubstring: "does not have format",
		},
		{
			flagValue:        ":abc",
			wantErrSubstring: "does not have format",
		},
		{
			flagValue:        "abc:",
			wantErrSubstring: "does not have format",
		},
		{
			// Control characters in the mountpoint are rejected.
			flagValue:        "/mnt/path\nwithnewline:abc",
			wantErrSubstring: "does not have format",
		},
	}
	for _, tc := range testCases {
		mountpoint, descriptor, err := matchMetadataFlag(tc.flagValue)
		if tc.wantErrSubstring != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstring) {
				t.Errorf("matchMetadataFlag(%q) error = %v, want error containing %q",
					tc.flagValue, err, tc.wantErrSubstring)
			}
			continue
		}
		if err != nil {
			t.Errorf("matchMetadataFlag(%q) returned unexpected error: %v", tc.flagValue, err)
			continue
		}
		if mountpoint != tc.wantMountpoint || descriptor != tc.wantDescriptor {
			t.Errorf("matchMetadataFlag(%q) = (%q, %q), want (%q, %q)",
				tc.flagValue, mountpoint, descriptor, tc.wantMountpoint, tc.wantDescriptor)
		}
	}
}

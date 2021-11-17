/*
 * config_test.go - Tests the processing of the config file
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
	"bytes"
	"testing"

	"github.com/golang/protobuf/proto"
)

var testConfig = &Config{
	Source: SourceType_custom_passphrase,
	HashCosts: &HashingCosts{
		Time:        10,
		Memory:      1 << 12,
		Parallelism: 8,
	},
	Options: DefaultOptions,
}

var testConfigString = `{
	"source": "custom_passphrase",
	"hash_costs": {
		"time": "10",
		"memory": "4096",
		"parallelism": "8"
	},
	"options": {
		"padding": "32",
		"contents": "AES_256_XTS",
		"filenames": "AES_256_CTS",
		"policy_version": "1"
	},
	"use_fs_keyring_for_v1_policies": false,
	"metadata_dir": ""
}
`

// Makes sure that writing a config and reading it back gives the same thing.
func TestWrite(t *testing.T) {
	var b bytes.Buffer
	err := WriteConfig(testConfig, &b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("json encoded config:\n%s", b.String())
	if b.String() != testConfigString {
		t.Errorf("did not match: %s", testConfigString)
	}
}

func TestRead(t *testing.T) {
	buf := bytes.NewBufferString(testConfigString)
	cfg, err := ReadConfig(buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("decoded config:\n%s", cfg)
	if !proto.Equal(cfg, testConfig) {
		t.Errorf("did not match: %s", testConfig)
	}
}

// Makes sure we can parse a legacy config file that doesn't have the fields
// that were added later and that has the removed "compatibility" field.
func TestOptionalFields(t *testing.T) {
	contents := `{
		"source": "custom_passphrase",
		"hash_costs": {
			"time": "10",
			"memory": "4096",
			"parallelism": "8"
		},
		"compatibility": "legacy",
		"options": {
			"padding": "32",
			"contents": "AES_256_XTS",
			"filenames": "AES_256_CTS"
		}
	}
	`
	buf := bytes.NewBufferString(contents)
	cfg, err := ReadConfig(buf)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GetUseFsKeyringForV1Policies() {
		t.Error("use_fs_keyring_for_v1_policies should be false, but was true")
	}
	if cfg.GetMetadataDir() != "" {
		t.Errorf("metadata_dir should be empty, but was %s", cfg.GetMetadataDir())
	}
	if cfg.Options.PolicyVersion != 0 {
		t.Errorf("policy version should be 0, but was %d", cfg.Options.PolicyVersion)
	}
	if err = cfg.CheckValidity(); err != nil {
		t.Error(err)
	}
	// CheckValidity() should change an unset policy version to 1.
	if cfg.Options.PolicyVersion != 1 {
		t.Errorf("policy version should be 1 now, but was %d", cfg.Options.PolicyVersion)
	}
}

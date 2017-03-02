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
	"reflect"
	"testing"
)

var testConfig = &Config{
	Source: SourceType_custom_passphrase,
	HashCosts: &HashingCosts{
		Time:        10,
		Memory:      1 << 12,
		Parallelism: 8,
	},
	Compatibility: "",
	Options: &EncryptionOptions{
		Padding:       32,
		ContentsMode:  EncryptionMode_XTS,
		FilenamesMode: EncryptionMode_CTS,
	},
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
		"contents_mode": "XTS",
		"filenames_mode": "CTS"
	}
}`

// Makes sure that writing a config and reading it back gives the same thing.
func TestWrite(t *testing.T) {
	str, err := WriteConfig(testConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("json encoded config:\n%s", str)
	if str != testConfigString {
		t.Errorf("did not match: %s", testConfigString)
	}
}

func TestRead(t *testing.T) {
	cfg, err := ReadConfig(testConfigString)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("decoded config:\n%s", cfg)
	if !reflect.DeepEqual(cfg, testConfig) {
		t.Errorf("did not match: %s", testConfig)
	}
}

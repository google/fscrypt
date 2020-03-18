/*
 * config_test.go - tests for creating the config file
 *
 * Copyright 2019 Google LLC
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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/google/fscrypt/metadata"
)

// Test that the global config file is created with mode 0644, regardless of the
// current umask.
func TestConfigFileIsCreatedWithCorrectMode(t *testing.T) {
	oldMask := unix.Umask(0)
	defer unix.Umask(oldMask)
	unix.Umask(0077)

	tempDir, err := ioutil.TempDir("", "fscrypt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	ConfigFileLocation = filepath.Join(tempDir, "test.conf")

	if err = CreateConfigFile(time.Millisecond, 0); err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(ConfigFileLocation)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0644 {
		t.Error("Expected newly created config file to have mode 0644")
	}
}

func TestCreateConfigFileV2Policy(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "fscrypt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	ConfigFileLocation = filepath.Join(tempDir, "test.conf")

	if err = CreateConfigFile(time.Millisecond, 2); err != nil {
		t.Fatal(err)
	}

	var config *metadata.Config
	config, err = getConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Options.PolicyVersion != 2 {
		t.Error("Expected PolicyVersion 2")
	}
}

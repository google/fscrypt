/*
 * config_test.go - tests for creating new contexts
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
	"os"
	"testing"

	"fscrypt/filesystem"
)

var mountpoint = os.Getenv("TEST_FILESYSTEM_ROOT")

// Makes a context using the testing locations for the filesystem and
// configuration file.
func makeContext() (*Context, error) {
	if err := CreateConfigFile(testTime, true); err != nil {
		return nil, err
	}

	mnt := filesystem.Mount{Path: mountpoint}
	if err := mnt.Setup(); err != nil {
		return nil, err
	}

	return NewContextFromMountpoint(mountpoint)
}

// Cleans up the testing config file and testing filesystem data.
func cleaupContext() {
	os.RemoveAll(ConfigFileLocation)
	mnt := filesystem.Mount{Path: mountpoint}
	mnt.RemoveAllMetadata()
}

// Tests that we can create a context
func TestSetupContext(t *testing.T) {
	_, err := makeContext()
	defer cleaupContext()
	if err != nil {
		t.Fatal(err)
	}

}

// Tests that we cannot create a context without a config file.
func TestNoConfigFile(t *testing.T) {
	mnt := filesystem.Mount{Path: mountpoint}
	if err := mnt.Setup(); err != nil {
		t.Fatal(err)
	}

	_, err := NewContextFromMountpoint(mountpoint)
	defer cleaupContext()

	if err == nil {
		t.Error("should not be able to create context without config file")
	}
}

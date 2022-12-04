/*
 * path_test.go - Tests for path utilities.
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

package filesystem

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/fscrypt/util"
)

func TestDeviceNumber(t *testing.T) {
	num, err := getDeviceNumber("/NONEXISTENT")
	if num != 0 || err == nil {
		t.Error("Should have failed to get device number of nonexistent file")
	}
	// /dev/null is always device 1:3 on Linux.
	num, err = getDeviceNumber("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	if str := num.String(); str != "1:3" {
		t.Errorf("Wrong device number string: %q", str)
	}
	if str := fmt.Sprintf("%v", num); str != "1:3" {
		t.Errorf("Wrong device number string: %q", str)
	}
	var num2 DeviceNumber
	num2, err = newDeviceNumberFromString("1:3")
	if err != nil {
		t.Error("Failed to parse device number")
	}
	if num2 != num {
		t.Errorf("Wrong device number: %d", num2)
	}
	num2, err = newDeviceNumberFromString("foo")
	if num2 != 0 || err == nil {
		t.Error("Should have failed to parse invalid device number")
	}
}

func TestHaveReadAccessTo(t *testing.T) {
	if util.IsUserRoot() {
		t.Skip("This test cannot be run as root")
	}
	file, err := os.CreateTemp("", "fscrypt_test")
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	defer os.Remove(file.Name())

	testCases := map[os.FileMode]bool{
		0444: true,
		0400: true,
		0000: false,
		0040: false, // user bits take priority in Linux
		0004: false, // user bits take priority in Linux
	}
	for mode, readable := range testCases {
		if err := os.Chmod(file.Name(), mode); err != nil {
			t.Error(err)
		}
		if HaveReadAccessTo(file.Name()) != readable {
			t.Errorf("Expected readable=%v on mode=0%03o", readable, mode)
		}
	}
}

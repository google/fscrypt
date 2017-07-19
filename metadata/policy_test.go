/*
 * policy_test.go - Tests the getting/setting of encryption policies
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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/fscrypt/util"
)

const goodDescriptor = "0123456789abcdef"

var goodPolicy = &PolicyData{
	KeyDescriptor: goodDescriptor,
	Options:       DefaultOptions,
}

// Creates a temporary directory for testing.
func createTestDirectory(t *testing.T) (directory string, err error) {
	baseDirectory, err := util.TestRoot()
	if err != nil {
		t.Skip(err)
	}
	if s, err := os.Stat(baseDirectory); err != nil || !s.IsDir() {
		return "", fmt.Errorf("test directory %q is not valid", baseDirectory)
	}

	directoryPath := filepath.Join(baseDirectory, "test")
	return directoryPath, os.MkdirAll(directoryPath, os.ModePerm)
}

// Makes a test directory, makes a file in the directory, and fills the file
// with data. Returns the directory name, file name, and error (if one).
func createTestFile(t *testing.T) (directory, file string, err error) {
	if directory, err = createTestDirectory(t); err != nil {
		return
	}
	// Cleanup if the file creation fails
	defer func() {
		if err != nil {
			os.RemoveAll(directory)
		}
	}()

	filePath := filepath.Join(directory, "test.txt")
	fileHandle, err := os.Create(filePath)
	if err != nil {
		return directory, filePath, err
	}
	defer fileHandle.Close()

	_, err = fileHandle.Write([]byte("Here is some test data!\n"))
	return directory, filePath, err
}

// Tests that we can set a policy on an empty directory
func TestSetPolicyEmptyDirectory(t *testing.T) {
	directory, err := createTestDirectory(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)

	if err = SetPolicy(directory, goodPolicy); err != nil {
		t.Error(err)
	}
}

// Tests that we cannot set a policy on a nonempty directory
func TestSetPolicyNonemptyDirectory(t *testing.T) {
	directory, _, err := createTestFile(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)

	if err = SetPolicy(directory, goodPolicy); err == nil {
		t.Error("should have failed to set policy on a nonempty directory")
	}
}

// Tests that we cannot set a policy on a file
func TestSetPolicyFile(t *testing.T) {
	directory, file, err := createTestFile(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)

	if err = SetPolicy(file, goodPolicy); err == nil {
		t.Error("should have failed to set policy on a file")
	}
}

// Tests that we fail when using bad policies
func TestSetPolicyBadDescriptors(t *testing.T) {
	// Policies that are too short, have invalid chars, or are too long
	badDescriptors := []string{"123456789abcde", "xxxxxxxxxxxxxxxx", "0123456789abcdef00"}
	for _, badDescriptor := range badDescriptors {
		badPolicy := &PolicyData{KeyDescriptor: badDescriptor, Options: DefaultOptions}
		directory, err := createTestDirectory(t)
		if err != nil {
			t.Fatal(err)
		}

		if err = SetPolicy(directory, badPolicy); err == nil {
			t.Errorf("descriptor %q should have made SetPolicy fail", badDescriptor)
		}
		os.RemoveAll(directory)
	}
}

// Tests that we get back the same policy that we set on a directory
func TestGetPolicyEmptyDirectory(t *testing.T) {
	directory, err := createTestDirectory(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)

	var actualPolicy *PolicyData
	if err = SetPolicy(directory, goodPolicy); err != nil {
		t.Fatal(err)
	}
	if actualPolicy, err = GetPolicy(directory); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(actualPolicy, goodPolicy) {
		t.Errorf("policy %+v does not equal expected policy %+v", actualPolicy, goodPolicy)
	}
}

// Tests that we cannot get a policy on an unencrypted directory
func TestGetPolicyUnencrypted(t *testing.T) {
	directory, err := createTestDirectory(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)

	if _, err = GetPolicy(directory); err == nil {
		t.Error("should have failed to set policy on a file")
	}
}

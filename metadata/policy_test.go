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
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/google/fscrypt/util"
)

const goodV1Descriptor = "0123456789abcdef"

var goodV1Policy = &PolicyData{
	KeyDescriptor: goodV1Descriptor,
	Options:       DefaultOptions,
}

var goodV2EncryptionOptions = &EncryptionOptions{
	Padding:       32,
	Contents:      EncryptionOptions_AES_256_XTS,
	Filenames:     EncryptionOptions_AES_256_CTS,
	PolicyVersion: 2,
}

var goodV2Policy = &PolicyData{
	KeyDescriptor: "0123456789abcdef0123456789abcdef",
	Options:       goodV2EncryptionOptions,
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

	if err = SetPolicy(directory, goodV1Policy); err != nil {
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

	if err = SetPolicy(directory, goodV1Policy); err == nil {
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

	if err = SetPolicy(file, goodV1Policy); err == nil {
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
	if err = SetPolicy(directory, goodV1Policy); err != nil {
		t.Fatal(err)
	}
	if actualPolicy, err = GetPolicy(directory); err != nil {
		t.Fatal(err)
	}

	if !proto.Equal(actualPolicy, goodV1Policy) {
		t.Errorf("policy %+v does not equal expected policy %+v", actualPolicy, goodV1Policy)
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

func requireV2PolicySupport(t *testing.T, directory string) {
	file, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	err = getPolicyIoctl(file, unix.FS_IOC_GET_ENCRYPTION_POLICY_EX, nil)
	if err == ErrEncryptionNotSupported {
		t.Skip("No support for v2 encryption policies, skipping test")
	}
}

// Tests that a non-root user cannot set a v2 encryption policy unless the key
// has been added.
func TestSetV2PolicyNoKey(t *testing.T) {
	if util.IsUserRoot() {
		t.Skip("This test cannot be run as root")
	}
	directory, err := createTestDirectory(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	requireV2PolicySupport(t, directory)

	err = SetPolicy(directory, goodV2Policy)
	if err == nil {
		t.Error("shouldn't have been able to set v2 policy without key added")
	}
}

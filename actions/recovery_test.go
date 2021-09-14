/*
 * recovery_test.go - tests for recovery passphrases
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
	"strings"
	"testing"

	"github.com/google/fscrypt/crypto"
)

func TestRecoveryPassphrase(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "fscrypt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	recoveryFile := filepath.Join(tempDir, "recovery.txt")

	firstProtector, policy, err := makeBoth()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupPolicy(policy)
	defer cleanupProtector(firstProtector)

	// Add a recovery passphrase and verify that it worked correctly.
	passphrase, recoveryProtector, err := AddRecoveryPassphrase(policy, "foo")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupProtector(recoveryProtector)
	if passphrase.Len() != 20 {
		t.Error("Recovery passphrase has wrong length")
	}
	if recoveryProtector.data.Name != "Recovery passphrase for foo" {
		t.Error("Recovery passphrase protector has wrong name")
	}
	if len(policy.ProtectorDescriptors()) != 2 {
		t.Error("There should be 2 protectors now")
	}
	getPassphraseFn := func(info ProtectorInfo, retry bool) (*crypto.Key, error) {
		return passphrase.Clone()
	}
	recoveryProtector.Lock()
	if err = recoveryProtector.Unlock(getPassphraseFn); err != nil {
		t.Fatal(err)
	}

	// Test writing the recovery instructions.
	if err = WriteRecoveryInstructions(passphrase, recoveryProtector, policy,
		recoveryFile); err != nil {
		t.Fatal(err)
	}
	contentsBytes, err := ioutil.ReadFile(recoveryFile)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(contentsBytes)
	if !strings.Contains(contents, string(passphrase.Data())) {
		t.Error("Recovery instructions don't actually contain the passphrase!")
	}

	// Test for protector naming collision.
	if passphrase, recoveryProtector, err = AddRecoveryPassphrase(policy, "foo"); err != nil {
		t.Fatal(err)
	}
	defer cleanupProtector(recoveryProtector)
	if recoveryProtector.data.Name != "Recovery passphrase for foo (2)" {
		t.Error("Recovery passphrase protector has wrong name (after naming collision)")
	}
}

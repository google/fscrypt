/*
 * protector_test.go - tests for creating protectors
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
	"bytes"
	"testing"

	"github.com/pkg/errors"

	. "fscrypt/crypto"
)

const testProtectorName = "my favorite protector"
const testProtectorName2 = testProtectorName + "2"

var errCallback = errors.New("bad callback")

func goodCallback(info ProtectorInfo, retry bool) (*Key, error) {
	return NewFixedLengthKeyFromReader(bytes.NewReader(timingPassphrase), len(timingPassphrase))
}

func badCallback(info ProtectorInfo, retry bool) (*Key, error) {
	return nil, errCallback
}

// Tests that we can create a valid protector.
func TestCreateProtector(t *testing.T) {
	p, err := CreateProtector(testContext, testProtectorName, goodCallback)
	if err != nil {
		t.Error(err)
	} else {
		p.Lock()
		p.Destroy()
	}
}

// Tests that a failure in the callback is relayed back to the caller.
func TestBadCallback(t *testing.T) {
	p, err := CreateProtector(testContext, testProtectorName, badCallback)
	if err == nil {
		p.Lock()
		p.Destroy()
	}
	if err != errCallback {
		t.Error("callback error was not relayed back to caller")
	}
}

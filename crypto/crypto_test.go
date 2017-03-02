/*
 * crypto_test.go - tests for the crypto package
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

package crypto

import (
	"bytes"
	"compress/zlib"
	"os"
	"testing"
)

// Reader that always returns the same byte
type ConstReader byte

func (r ConstReader) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = byte(r)
	}
	return len(b), nil
}

// Makes a key of the same repeating byte
func makeKey(b byte, n int) (*Key, error) {
	return NewFixedLengthKeyFromReader(ConstReader(b), n)
}

var fakeValidDescriptor = "0123456789abcdef"
var fakeInvalidDescriptor = "123456789abcdef"

var fakeValidPolicyKey, _ = makeKey(42, PolicyKeyLen)
var fakeInvalidPolicyKey, _ = makeKey(42, PolicyKeyLen-1)

// Tests the two ways of making keys
func TestMakeKeys(t *testing.T) {
	data := []byte("1234\n6789")

	key1, err := NewKeyFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, key1.data) {
		t.Error("Key from reader contained incorrect data")
	}

	key2, err := NewFixedLengthKeyFromReader(bytes.NewReader(data), 6)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte("1234\n6"), key2.data) {
		t.Error("Fixed length key from reader contained incorrect data")
	}
}

// Tests that wipe succeeds
func TestWipe(t *testing.T) {
	key, err := makeKey(1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Wipe(); err != nil {
		t.Error(err)
	}
}

// Making keys with negative length should fail
func TestInvalidLength(t *testing.T) {
	_, err := NewFixedLengthKeyFromReader(bytes.NewReader([]byte{1, 2, 3, 4}), -1)
	if err == nil {
		t.Error("Negative lengths should cause failure")
	}
}

// Test making keys of zero length
func TestZeroLength(t *testing.T) {
	key1, err := NewFixedLengthKeyFromReader(os.Stdin, 0)
	if err != nil {
		t.Fatal(err)
	}
	if key1.data != nil {
		t.Error("FIxed length key from reader contained data")
	}

	key2, err := NewKeyFromReader(bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if key2.data != nil {
		t.Error("Key from empty reader contained data")
	}
}

// Test making keys long enough that the keys will have to resize
func TestLongLength(t *testing.T) {
	// Key will have to resize 3 times
	data := bytes.Repeat([]byte{1}, os.Getpagesize()*5)
	key, err := NewKeyFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, key.data) {
		t.Error("Key contained incorrect data")
	}
}

// Adds a key with and without legacy (check keyctl to see the key identifiers).
func TestAddKeys(t *testing.T) {
	for _, service := range []string{ServiceDefault, ServiceExt4, ServiceF2FS} {
		if err := InsertPolicyKey(fakeValidPolicyKey, fakeValidDescriptor, service); err != nil {
			t.Error(err)
		}
	}
}

// Makes sure a key fails with bad descriptor, policy, or service
func TestBadAddKeys(t *testing.T) {
	if InsertPolicyKey(fakeInvalidPolicyKey, fakeValidDescriptor, ServiceDefault) == nil {
		t.Error("InsertPolicyKey should fail with bad policy key")
	}
	if InsertPolicyKey(fakeValidPolicyKey, fakeInvalidDescriptor, ServiceDefault) == nil {
		t.Error("InsertPolicyKey should fail with bad descriptor")
	}
	if InsertPolicyKey(fakeValidPolicyKey, fakeValidDescriptor, "ext4") == nil {
		t.Error("InsertPolicyKey should fail with bad service")
	}
}

// Check that we can create random keys. All this test does to test the
// "randomness" is generate a page of random bytes and attempts compression.
// If the data can be compressed it is probably not very random. This isn't
// indented to be a sufficient test for randomness (which is impossible), but a
// way to catch simple regressions (key is all zeros or contains a repeating
// pattern).
func TestRandomKeyGen(t *testing.T) {
	key, err := NewRandomKey(os.Getpagesize())
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()

	if didCompress(key.data) {
		t.Errorf("Random key (%d bytes) should not be compressible", key.Len())
	}
}

// didCompress checks if the given data can be compressed. Specifically, it
// returns true if running zlib on the provided input produces a shorter output.
func didCompress(input []byte) bool {
	var output bytes.Buffer

	w := zlib.NewWriter(&output)
	_, err := w.Write(input)
	w.Close()

	return err == nil && len(input) > output.Len()
}

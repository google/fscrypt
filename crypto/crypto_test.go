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
	"crypto/aes"
	"crypto/sha256"
	"fmt"
	"fscrypt/metadata"
	"fscrypt/util"
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
var fakeWrappingKey, _ = makeKey(17, InternalKeyLen)

// Checks that len(array) == expected
func lengthCheck(name string, array []byte, expected int) error {
	if len(array) != expected {
		return util.InvalidLengthError(name, expected, len(array))
	}
	return nil
}

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

// Checks that the input arrays are all distinct
func buffersDistinct(buffers ...[]byte) bool {
	for i := 0; i < len(buffers); i++ {
		for j := i + 1; j < len(buffers); j++ {
			if bytes.Equal(buffers[i], buffers[j]) {
				// Different entry, but equal arrays
				return false
			}
		}
	}
	return true
}

// Checks that our cryptographic operations all produce distinct data
func TestKeysAndOutputsDistinct(t *testing.T) {
	data, err := Wrap(fakeWrappingKey, fakeValidPolicyKey)
	if err != nil {
		t.Fatal(err)
	}

	encKey, authKey := stretchKey(fakeWrappingKey)

	if !buffersDistinct(fakeWrappingKey.data, fakeValidPolicyKey.data,
		encKey.data, authKey.data, data.IV, data.EncryptedKey, data.Hmac) {
		t.Error("Key wrapping produced duplicate data")
	}
}

// Check that Wrap() works with fixed keys
func TestWrapSucceeds(t *testing.T) {
	data, err := Wrap(fakeWrappingKey, fakeValidPolicyKey)
	if err != nil {
		t.Fatal(err)
	}

	if err = lengthCheck("IV", data.IV, aes.BlockSize); err != nil {
		t.Error(err)
	}
	if err = lengthCheck("Encrypted Key", data.EncryptedKey, PolicyKeyLen); err != nil {
		t.Error(err)
	}
	if err = lengthCheck("HMAC", data.Hmac, sha256.Size); err != nil {
		t.Error(err)
	}
}

// Checks that applying Wrap then Unwrap gives the original data
func testWrapUnwrapEqual(wrappingKey *Key, secretKey *Key) error {
	data, err := Wrap(wrappingKey, secretKey)
	if err != nil {
		return err
	}

	secret, err := Unwrap(wrappingKey, data)
	if err != nil {
		return err
	}
	defer secret.Wipe()

	if !bytes.Equal(secretKey.data, secret.data) {
		return fmt.Errorf("Got %x after wrap/unwrap with w=%x and s=%x",
			secret.data, wrappingKey.data, secretKey.data)
	}
	return nil
}

// Check that Unwrap(Wrap(x)) == x with fixed keys
func TestWrapUnwrapEqual(t *testing.T) {
	if err := testWrapUnwrapEqual(fakeWrappingKey, fakeValidPolicyKey); err != nil {
		t.Error(err)
	}
}

// Check that Unwrap(Wrap(x)) == x with random keys
func TestRandomWrapUnwrapEqual(t *testing.T) {
	for i := 0; i < 10; i++ {
		wk, err := NewRandomKey(InternalKeyLen)
		if err != nil {
			t.Fatal(err)
		}
		sk, err := NewRandomKey(InternalKeyLen)
		if err != nil {
			t.Fatal(err)
		}
		if err = testWrapUnwrapEqual(wk, sk); err != nil {
			t.Error(err)
		}
		wk.Wipe()
		sk.Wipe()
	}
}

// Check that Unwrap(Wrap(x)) == x with differing lengths of secret key
func TestDifferentLengthSecretKey(t *testing.T) {
	wk, err := makeKey(1, InternalKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		sk, err := makeKey(2, i)
		if err != nil {
			t.Fatal(err)
		}
		if err = testWrapUnwrapEqual(wk, sk); err != nil {
			t.Error(err)
		}
		sk.Wipe()
	}
}

// Wrong length of wrapping key should fail
func TestWrongWrappingKeyLength(t *testing.T) {
	_, err := Wrap(fakeValidPolicyKey, fakeWrappingKey)
	if err == nil {
		t.Fatal("using a policy key for wrapping should fail")
	}
}

// Wraping twice with the same keys should give different components
func TestWrapTwiceDistinct(t *testing.T) {
	data1, err := Wrap(fakeWrappingKey, fakeValidPolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	data2, err := Wrap(fakeWrappingKey, fakeValidPolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	if !buffersDistinct(data1.IV, data1.EncryptedKey, data1.Hmac,
		data2.IV, data2.EncryptedKey, data2.Hmac) {
		t.Error("Wrapping same keys twice should give distinct results")
	}
}

// Attempts to Unwrap data with key after altering tweek, should fail
func testFailWithTweek(key *Key, data *metadata.WrappedKeyData, tweek []byte) error {
	tweek[0]++
	_, err := Unwrap(key, data)
	tweek[0]--
	return err
}

// Wrapping then unwrapping with different components altered
func TestUnwrapWrongKey(t *testing.T) {
	data, err := Wrap(fakeWrappingKey, fakeValidPolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	if testFailWithTweek(fakeWrappingKey, data, fakeWrappingKey.data) == nil {
		t.Error("using a different wrapping key should make unwrap fail")
	}
}

func TestUnwrapWrongData(t *testing.T) {
	data, err := Wrap(fakeWrappingKey, fakeValidPolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	if testFailWithTweek(fakeWrappingKey, data, data.EncryptedKey) == nil {
		t.Error("changing encryption key should make unwrap fail")
	}
	if testFailWithTweek(fakeWrappingKey, data, data.IV) == nil {
		t.Error("changing IV should make unwrap fail")
	}
	if testFailWithTweek(fakeWrappingKey, data, data.Hmac) == nil {
		t.Error("changing HMAC should make unwrap fail")
	}
}

func BenchmarkWrap(b *testing.B) {
	for n := 0; n < b.N; n++ {
		Wrap(fakeWrappingKey, fakeValidPolicyKey)
	}
}

func BenchmarkUnwrap(b *testing.B) {
	data, _ := Wrap(fakeWrappingKey, fakeValidPolicyKey)

	for n := 0; n < b.N; n++ {
		Unwrap(fakeWrappingKey, data)
	}
}

func BenchmarkUnwrapNolock(b *testing.B) {
	UseMlock = false
	defer func() {
		UseMlock = true
	}()
	data, _ := Wrap(fakeWrappingKey, fakeValidPolicyKey)

	for n := 0; n < b.N; n++ {
		_, _ = Unwrap(fakeWrappingKey, data)
	}
}

func BenchmarkRandomWrapUnwrap(b *testing.B) {
	for n := 0; n < b.N; n++ {
		wk, _ := NewRandomKey(InternalKeyLen)
		sk, _ := NewRandomKey(InternalKeyLen)

		testWrapUnwrapEqual(wk, sk)
		// Must manually call wipe here, or test will use too much memory.
		wk.Wipe()
		sk.Wipe()
	}
}

/*
 * recovery_test.go - tests for recovery codes in the crypto package
 * tests key wrapping/unwrapping and key generation
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
	"fmt"
	"testing"

	"github.com/google/fscrypt/metadata"
)

const fakeSecretRecoveryCode = "EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJRG-EYTCMJQ="

var fakeSecretKey, _ = makeKey(38, metadata.PolicyKeyLen)

// Note that this function is INSECURE. FOR TESTING ONLY
func getRecoveryCodeFromKey(key *Key) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteRecoveryCode(key, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func getRandomRecoveryCodeBuffer() ([]byte, error) {
	key, err := NewRandomKey(metadata.PolicyKeyLen)
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	return getRecoveryCodeFromKey(key)
}

func getKeyFromRecoveryCode(buf []byte) (*Key, error) {
	return ReadRecoveryCode(bytes.NewReader(buf))
}

// Given a key, make a recovery code from that key, use that code to rederive
// another key and check if they are the same.
func testKeyEncodeDecode(key *Key) error {
	buf, err := getRecoveryCodeFromKey(key)
	if err != nil {
		return err
	}

	key2, err := getKeyFromRecoveryCode(buf)
	if err != nil {
		return err
	}
	defer key2.Wipe()

	if !bytes.Equal(key.data, key2.data) {
		return fmt.Errorf("encoding then decoding %x didn't yield the same key", key.data)
	}
	return nil
}

// Given a recovery code, make a key from that recovery code, use that key to
// rederive another recovery code and check if they are the same.
func testRecoveryDecodeEncode(buf []byte) error {
	key, err := getKeyFromRecoveryCode(buf)
	if err != nil {
		return err
	}
	defer key.Wipe()

	buf2, err := getRecoveryCodeFromKey(key)
	if err != nil {
		return err
	}

	if !bytes.Equal(buf, buf2) {
		return fmt.Errorf("decoding then encoding %x didn't yield the same key", buf)
	}
	return nil
}

func TestGetRandomRecoveryString(t *testing.T) {
	b, err := getRandomRecoveryCodeBuffer()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(b))
	// t.Fail() // Uncomment to see an example random recovery code
}

func TestFakeSecretKey(t *testing.T) {
	buf, err := getRecoveryCodeFromKey(fakeSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	recoveryCode := string(buf)
	if recoveryCode != fakeSecretRecoveryCode {
		t.Errorf("got '%s' instead of '%s'", recoveryCode, fakeSecretRecoveryCode)
	}
}

func TestEncodeDecode(t *testing.T) {
	key, err := NewRandomKey(metadata.PolicyKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()

	if err = testKeyEncodeDecode(key); err != nil {
		t.Error(err)
	}
}

func TestDecodeEncode(t *testing.T) {
	buf, err := getRandomRecoveryCodeBuffer()
	if err != nil {
		t.Fatal(err)
	}

	if err = testRecoveryDecodeEncode(buf); err != nil {
		t.Error(err)
	}
}

func TestWrongLengthError(t *testing.T) {
	key, err := NewRandomKey(metadata.PolicyKeyLen - 1)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()

	if _, err = getRecoveryCodeFromKey(key); err == nil {
		t.Error("key with wrong length should have failed to encode")
	}
}

func TestBadCharacterError(t *testing.T) {
	buf, err := getRandomRecoveryCodeBuffer()
	if err != nil {
		t.Fatal(err)
	}
	// Lowercase letters not allowed
	buf[3] = 'k'
	if key, err := getKeyFromRecoveryCode(buf); err == nil {
		key.Wipe()
		t.Error("lowercase letters should make decoding fail")
	}
}

func TestBadEndCharacterError(t *testing.T) {
	buf, err := getRandomRecoveryCodeBuffer()
	if err != nil {
		t.Fatal(err)
	}
	// Separator must be '-'
	buf[blockSize] = '_'
	if key, err := getKeyFromRecoveryCode(buf); err == nil {
		key.Wipe()
		t.Error("any separator that isn't '-' should make decoding fail")
	}
}

func BenchmarkEncode(b *testing.B) {
	b.StopTimer()

	key, err := NewRandomKey(metadata.PolicyKeyLen)
	if err != nil {
		b.Fatal(err)
	}
	defer key.Wipe()

	b.StartTimer()
	for n := 0; n < b.N; n++ {
		if _, err = getRecoveryCodeFromKey(key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	b.StopTimer()

	buf, err := getRandomRecoveryCodeBuffer()
	if err != nil {
		b.Fatal(err)
	}

	b.StartTimer()
	for n := 0; n < b.N; n++ {
		key, err := getKeyFromRecoveryCode(buf)
		if err != nil {
			b.Fatal(err)
		}
		key.Wipe()
	}
}

func BenchmarkEncodeDecode(b *testing.B) {
	b.StopTimer()

	key, err := NewRandomKey(metadata.PolicyKeyLen)
	if err != nil {
		b.Fatal(err)
	}
	defer key.Wipe()

	b.StartTimer()
	for n := 0; n < b.N; n++ {
		if err = testKeyEncodeDecode(key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeEncode(b *testing.B) {
	b.StopTimer()

	buf, err := getRandomRecoveryCodeBuffer()
	if err != nil {
		b.Fatal(err)
	}

	b.StartTimer()
	for n := 0; n < b.N; n++ {
		if err = testRecoveryDecodeEncode(buf); err != nil {
			b.Fatal(err)
		}
	}
}

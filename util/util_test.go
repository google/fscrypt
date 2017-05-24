/*
 * util_test.go - Tests the util package
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

package util

import (
	"testing"
)

const offset = 3

// Make sure the address behaves well under slicing
func TestPtrOffset(t *testing.T) {
	arr := []byte{'a', 'b', 'c', 'd'}
	i1 := uintptr(Ptr(arr[offset:]))
	i2 := uintptr(Ptr(arr))

	if i1 != i2+offset {
		t.Fatalf("pointers %v and %v do not have an offset of %v", i1, i2, offset)
	}
}

// Make sure NeverError actually panics
func TestNeverErrorPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NeverError did not panic")
		}
	}()

	err := SystemError("Hello")
	NeverError(err)
}

// Make sure NeverError doesn't panic on nil
func TestNeverErrorNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NeverError panicked")
		}
	}()

	NeverError(nil)
}

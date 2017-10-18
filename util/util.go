/*
 * util.go - Various helpers used throughout fscrypt
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

// Package util contains useful components for simplifying Go code.
//
// The package contains common error types (errors.go) and functions for
// converting arrays to pointers.
package util

import (
	"math"
	"strconv"
	"unsafe"
)

// Ptr converts an Go byte array to a pointer to the start of the array.
func Ptr(slice []byte) unsafe.Pointer {
	if len(slice) == 0 {
		return nil
	}
	return unsafe.Pointer(&slice[0])
}

// ByteSlice takes a pointer to some data and views it as a slice of bytes.
// Note, indexing into this slice is unsafe.
func ByteSlice(ptr unsafe.Pointer) []byte {
	// Silce must fix in 32-bit address space to build on 32-bit platforms.
	return (*[math.MaxInt32]byte)(ptr)[:]
}

// PointerSlice takes a pointer to an array of pointers and views it as a slice
// of pointers. Note, indexing into this slice is unsafe.
func PointerSlice(ptr unsafe.Pointer) []unsafe.Pointer {
	// Silce must fix in 32-bit address space to build on 32-bit platforms.
	return (*[math.MaxInt32 / 4]unsafe.Pointer)(ptr)[:]
}

// Index returns the first index i such that inVal == inArray[i].
// ok is true if we find a match, false otherwise.
func Index(inVal int64, inArray []int64) (index int, ok bool) {
	for index, val := range inArray {
		if val == inVal {
			return index, true
		}
	}
	return 0, false
}

// Lookup finds inVal in inArray and returns the corresponding element in
// outArray. Specifically, if inVal == inArray[i], outVal == outArray[i].
// ok is true if we find a match, false otherwise.
func Lookup(inVal int64, inArray, outArray []int64) (outVal int64, ok bool) {
	index, ok := Index(inVal, inArray)
	if !ok {
		return 0, false
	}
	return outArray[index], true
}

// MinInt returns the lesser of a and b.
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MaxInt returns the greater of a and b.
func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// MinInt64 returns the lesser of a and b.
func MinInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// AtoiOrPanic converts a string to an int or it panics. Should only be used in
// situations where the input MUST be a decimal number.
func AtoiOrPanic(input string) int {
	i, err := strconv.Atoi(input)
	if err != nil {
		panic(err)
	}
	return i
}

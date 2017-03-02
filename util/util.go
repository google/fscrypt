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
	"io"
	"unsafe"
)

// ErrReader wraps an io.Reader, passing along calls to Read() until a read
// fails. Then, the error is stored, and all subsequent calls to Read() do
// nothing. This allows you to write code which has many subsequent reads and
// do all of the error checking at the end. For example:
//
//  r := NewErrReader(reader)
//  r.Read(foo)
//  io.ReadFull(r, bar)
//  if r.Err() != nil {
//    // Handle error
//  }
//
// Taken from https://blog.golang.org/errors-are-values by Rob Pike.
type ErrReader struct {
	r   io.Reader
	err error
}

// NewErrReader creates an ErrReader which wraps the provided reader.
func NewErrReader(reader io.Reader) *ErrReader {
	return &ErrReader{r: reader, err: nil}
}

// Read runs ReadFull on the wrapped reader if no errors have occurred.
// Otherwise, the previous error is just returned and no reads are attempted.
func (e *ErrReader) Read(p []byte) (n int, err error) {
	if e.err == nil {
		n, e.err = io.ReadFull(e.r, p)
	}
	return n, e.err
}

// Err returns the first encountered err (or nil if no errors occurred).
func (e *ErrReader) Err() error {
	return e.err
}

// ErrWriter works exactly like ErrReader, except with io.Writer.
type ErrWriter struct {
	w   io.Writer
	err error
}

// NewErrWriter creates an ErrWriter which wraps the provided reader.
func NewErrWriter(writer io.Writer) *ErrWriter {
	return &ErrWriter{w: writer, err: nil}
}

// Write runs the wrapped writer's Write if no errors have occurred. Otherwise,
// the previous error is just returned and no writes are attempted.
func (e *ErrWriter) Write(p []byte) (n int, err error) {
	if e.err == nil {
		n, e.err = e.w.Write(p)
	}
	return n, e.err
}

// Err returns the first encountered err (or nil if no errors occurred).
func (e *ErrWriter) Err() error {
	return e.err
}

// Ptr converts an Go byte array to a pointer to the start of the array.
func Ptr(slice []byte) unsafe.Pointer {
	return unsafe.Pointer(&slice[0])
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

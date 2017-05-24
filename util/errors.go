/*
 * errors.go - Custom errors and error functions used by fscrypt
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
	"fmt"
	"io"
	"log"
	"os"
)

// ErrReader wraps an io.Reader, passing along calls to Read() until a read
// fails. Then, the error is stored, and all subsequent calls to Read() do
// nothing. This allows you to write code which has many subsequent reads and
// do all of the error checking at the end. For example:
//
//	r := NewErrReader(reader)
//	r.Read(foo)
//	r.Read(bar)
//	r.Read(baz)
//	if r.Err() != nil {
//		// Handle error
//	}
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

// InvalidInput is an error that should indicate either bad input from a caller
// of a public package function.
type InvalidInput string

func (i InvalidInput) Error() string {
	return "invalid input: " + string(i)
}

// InvalidLengthError indicates name should have had length expected.
func InvalidLengthError(name string, expected int, actual int) InvalidInput {
	message := fmt.Sprintf("length of %s: expected=%d, actual=%d", name, expected, actual)
	return InvalidInput(message)
}

// SystemError is an error that should indicate something has gone wrong in the
// underlying system (syscall failure, bad ioctl, etc...).
type SystemError string

func (s SystemError) Error() string {
	return "system error: " + string(s)
}

// NeverError panics if a non-nil error is passed in. It should be used to check
// for logic errors, not to handle recoverable errors.
func NeverError(err error) {
	if err != nil {
		log.Panicf("NeverError() check failed: %v", err)
	}
}

// UnderlyingError returns the underlying error for known os error types and
// logs the full error. From: src/os/error.go
func UnderlyingError(err error) error {
	var newErr error
	switch typedErr := err.(type) {
	case *os.PathError:
		newErr = typedErr.Err
	case *os.LinkError:
		newErr = typedErr.Err
	case *os.SyscallError:
		newErr = typedErr.Err
	default:
		return err
	}
	log.Print(err)
	return newErr
}

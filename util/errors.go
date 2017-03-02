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
	"log"
)

// InvalidInputF creates an error that should indicate either bad input from a
// caller of a public library function or bad user input.
func InvalidInputF(format string, a ...interface{}) error {
	return fmt.Errorf("invalid input: "+format, a...)
}

// InvalidLengthError indicates name should have had length expected.
func InvalidLengthError(name string, expected int, actual int) error {
	return InvalidInputF("expected %s of length %d, actual length was %d", name, expected, actual)
}

// SystemErrorF creates an error that should indicate something has gone wrong
// in the underlying system (syscall failure, bad ioctl, etc...).
func SystemErrorF(format string, a ...interface{}) error {
	return fmt.Errorf("system error: "+format, a...)
}

// NeverError panics if a non-nil error is passed in. It should be used to check
// for logic errors, not to handle recoverable errors.
func NeverError(err error) {
	if err != nil {
		log.Panicf("NeverError() check failed: %v", err)
	}
}

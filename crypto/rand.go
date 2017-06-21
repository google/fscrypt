/*
 * rand.go - Reader used to generate secure random data for fscrypt.
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
	"io"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// NewRandomBuffer uses the Linux Getrandom() syscall to create random bytes. If
// the operating system has insufficient randomness, the buffer creation will
// fail. This is an improvement over Go's built-in crypto/rand which will still
// return bytes if the system has insufficiency entropy.
// 	See: https://github.com/golang/go/issues/19274
//
// While this syscall was only introduced in Kernel v3.17, it predates the
// introduction of filesystem encryption, so it introduces no additional
// compatibility issues.
func NewRandomBuffer(length int) ([]byte, error) {
	buffer := make([]byte, length)
	if _, err := io.ReadFull(randReader{}, buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

// NewRandomKey creates a random key of the specified length. This function uses
// the same random number generation process a NewRandomBuffer.
func NewRandomKey(length int) (*Key, error) {
	return NewFixedLengthKeyFromReader(randReader{}, length)
}

// randReader just calls into Getrandom, so no internal data is needed.
type randReader struct{}

func (r randReader) Read(buffer []byte) (int, error) {
	n, err := unix.Getrandom(buffer, unix.GRND_NONBLOCK)
	switch err {
	case nil:
		return n, nil
	case unix.EAGAIN:
		return 0, errors.Wrap(ErrGetrandomFail, "insufficient entropy in pool")
	case unix.ENOSYS:
		return 0, errors.Wrap(ErrGetrandomFail, "kernel must be v3.17 or later")
	default:
		return 0, errors.Wrap(ErrGetrandomFail, err.Error())
	}
}

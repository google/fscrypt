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

	"golang.org/x/sys/unix"

	"fscrypt/util"
)

/*
RandReader uses the Linux Getrandom() syscall to read random bytes. If the
operating system has insufficient randomness, the read will fail. This is an
improvement over Go's built-in crypto/rand which will still return bytes if the
system has insufficiency entropy (https://github.com/golang/go/issues/19274).

While this syscall was only introduced in Kernel v3.17, it predates the
introduction of filesystem encryption, so it introduces no additional
compatibility issues.
*/
var RandReader io.Reader = randReader{}

// As we just call into Getrandom, no internal data is needed.
type randReader struct{}

func (r randReader) Read(buffer []byte) (int, error) {
	n, err := unix.Getrandom(buffer, unix.GRND_NONBLOCK)
	switch err {
	case nil:
		return n, nil
	case unix.EAGAIN:
		return 0, util.SystemErrorF("entropy pool not yet initialized")
	case unix.ENOSYS:
		return 0, util.SystemErrorF("getrandom not implemented; kernel must be v3.17 or later")
	default:
		return 0, util.SystemErrorF("cannot get randomness: %v", err)
	}
}

// NewRandomKey creates a random key (from RandReader) of the specified length.
func NewRandomKey(length int) (*Key, error) {
	return NewFixedLengthKeyFromReader(RandReader, length)
}

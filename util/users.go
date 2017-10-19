/*
 * util.go - Functions for dealing with users
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
	"os"
	"os/user"
	"strconv"
)

// CurrentUserID returns the uid of the effective user.
func CurrentUserID() int {
	return os.Geteuid()
}

// GetUser returns the user entry corresponding to the provided uid.
func GetUser(uid int) *user.User {
	uidString := strconv.Itoa(uid)
	foundUser, err := user.LookupId(uidString)
	if err != nil {
		return &user.User{
			Uid:      uidString,
			Username: fmt.Sprintf("[uid=%d]", uid),
		}
	}
	return foundUser
}

// CurrentUser returns the user entry for the effective user.
func CurrentUser() *user.User {
	return GetUser(CurrentUserID())
}

// CheckIfRoot returns ErrNotRoot if the current user is not the root user.
func CheckIfRoot() error {
	if id := CurrentUserID(); id != 0 {
		return ErrNotRoot
	}
	return nil
}

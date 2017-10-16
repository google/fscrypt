/*
 * strings.go - File which contains the specific strings used for output and
 * formatting in fscrypt.
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

package main

import (
	"fmt"
)

// Argument usage strings
const (
	directoryArg    = "DIRECTORY"
	mountpointArg   = "MOUNTPOINT"
	pathArg         = "PATH"
	mountpointIDArg = mountpointArg + ":ID"
)

// Add words to this map if pluralization does not just involve adding an s.
var plurals = map[string]string{
	"policy": "policies",
}

// pluralize prints our the correct pluralization of a work along with the
// specified count. This means pluralize(1, "policy") = "1 policy" but
// pluralize(2, "policy") = "2 policies"
func pluralize(count int, word string) string {
	if count != 1 {
		if plural, ok := plurals[word]; ok {
			word = plural
		} else {
			word += "s"
		}
	}
	return fmt.Sprintf("%d %s", count, word)
}

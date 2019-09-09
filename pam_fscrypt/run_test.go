/*
 * run_test.go - tests that the PAM helper functions work properly
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
	"testing"
)

func TestParseArgsEmpty(t *testing.T) {
	// An empty argv should create a map with no entries
	args := parseArgs(0, nil)
	if args == nil {
		t.Fatal("args map should not be nil")
	}
	if len(args) > 0 {
		t.Fatal("args map should not have any entries")
	}
}

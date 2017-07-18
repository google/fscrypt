/*
 * mountpoint_test.go - Tests for reading information about all mountpoints.
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

package filesystem

import (
	"testing"
)

func TestLoadMountInfo(t *testing.T) {
	if err := UpdateMountInfo(); err != nil {
		t.Error(err)
	}
}

// Benchmarks how long it takes to update the mountpoint data
func BenchmarkLoadFirst(b *testing.B) {
	for n := 0; n < b.N; n++ {
		err := UpdateMountInfo()
		if err != nil {
			b.Fatal(err)
		}
	}
}

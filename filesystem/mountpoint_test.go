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
	"fmt"
	"testing"
)

func printMountInfo() {
	fmt.Println("\nBy Mountpoint:")
	for _, mnt := range mountsByPath {
		fmt.Println("\t" + mnt.Path)
		fmt.Println("\t\tFilesystem: " + mnt.Filesystem)
		fmt.Printf("\t\tOptions:    %v\n", mnt.Options)
		fmt.Println("\t\tDevice:     " + mnt.Device)
	}

	fmt.Println("\nBy Device:")
	for device, mnts := range mountsByDevice {
		fmt.Println("\t" + device)
		for _, mnt := range mnts {
			fmt.Println("\t\tPath: " + mnt.Path)
		}
	}
}

func printSupportedMounts() {
	fmt.Println("\nSupported Mountpoints:")
	for _, mnt := range AllSupportedFilesystems() {
		fmt.Println("\t" + mnt.Path)
		fmt.Println("\t\tFilesystem: " + mnt.Filesystem)
		fmt.Printf("\t\tOptions:    %v\n", mnt.Options)
		fmt.Println("\t\tDevice:     " + mnt.Device)
	}
}

func TestLoadMountInfo(t *testing.T) {
	if err := UpdateMountInfo(); err != nil {
		t.Error(err)
	}
}

func TestPrintMountInfo(t *testing.T) {
	// Uncomment to see the mount info in the tests
	// printMountInfo()
	// printSupportedMounts()
	// t.Fail()
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

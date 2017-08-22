/*
 * cache.go - Handles cache clearing and management.
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

package security

import (
	"log"
	"os"
)

// DropInodeCache instructs the kernel to clear the global cache of inodes and
// dentries. This has the effect of making encrypted directories whose keys
// are not present no longer accessible. Requires root privileges.
func DropInodeCache() error {
	log.Print("dropping page caches")
	// See: https://www.kernel.org/doc/Documentation/sysctl/vm.txt
	file, err := os.OpenFile("/proc/sys/vm/drop_caches", os.O_WRONLY|os.O_SYNC, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	// "2" just clears the inodes and dentries
	_, err = file.WriteString("2")
	return err
}

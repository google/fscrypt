/*
 * path.go - Utility functions for dealing with filesystem paths
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
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// We only check the unix permissions and the sticky bit
const permMask = os.ModeSticky | os.ModePerm

// cannonicalizePath turns path into an absolute path without symlinks.
func cannonicalizePath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)

	// Get a better error if we have an invalid path
	if pathErr, ok := err.(*os.PathError); ok {
		err = errors.Wrap(pathErr.Err, pathErr.Path)
	}

	return path, err
}

// loggedStat runs os.Stat, but it logs the error if stat returns any error
// other than nil or IsNotExist.
func loggedStat(name string) (os.FileInfo, error) {
	info, err := os.Stat(name)
	if err != nil && !os.IsNotExist(err) {
		log.Print(err)
	}
	return info, err
}

// isDir returns true if the path exists and is that of a directory.
func isDir(path string) bool {
	info, err := loggedStat(path)
	return err == nil && info.IsDir()
}

// isDevice returns true if the path exists and is that of a directory.
func isDevice(path string) bool {
	info, err := loggedStat(path)
	return err == nil && info.Mode()&os.ModeDevice != 0
}

// isDirCheckPerm returns true if the path exists and is a directory. If the
// specified permissions and sticky bit of mode do not match the path, and error
// is logged.
func isDirCheckPerm(path string, mode os.FileMode) bool {
	info, err := loggedStat(path)
	// Check if directory
	if err != nil || !info.IsDir() {
		return false
	}
	// Check for bad permissions
	if info.Mode()&permMask != mode&permMask {
		log.Printf("directory %s has incorrect permissions", path)
	}
	return true
}

// isRegularFile returns true if the path exists and is that of a regular file.
func isRegularFile(path string) bool {
	info, err := loggedStat(path)
	return err == nil && info.Mode().IsRegular()
}

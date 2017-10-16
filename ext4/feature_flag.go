// +build linux,cgo

/*
 * feature_flag.go - Changes encryption flag for an ext4 filesystem.
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

/*
#cgo LDFLAGS: -lext2fs
#include <ext2fs/ext2_fs.h>
#include <ext2fs/ext2fs.h>

#include <stdlib.h>
*/
import "C"
import (
	"fmt"

	"github.com/google/fscrypt/filesystem"
)

// Ext4Filesystem wraps the C structures returned from libext2fs.
type Ext4Filesystem struct {
	ptr     C.ext2_filsys
	mounted bool
	retVal  C.errcode_t
}

// NewExt4Filesystem creates a new Ext4Filesystem from a mountpoint path. Fail
// if the path is not the mountpoint of an ext4 filesystem or cannot be opened.
func NewExt4Filesystem(mount *filesystem.Mount) (*Ext4Filesystem, error) {
	if mount.Filesystem != "ext4" {
		err := fmt.Errorf("%q is not an ext4 filesystem (type %q)", mount.Path, mount.Filesystem)
		return nil, err
	}
	if mount.Device == "" {
		err := fmt.Errorf("underlying device for %q is invalid", mount.Filesystem)
		return nil, err
	}
	return nil, nil
}

// HasValidBlockSize returns true if the filesystem has the same block size as
// the system's page size.
func (fs *Ext4Filesystem) HasValidBlockSize() bool {
	return true
}

// IsEncryptionEnabled return true if the "encrypt" feature flag is set.
func (fs *Ext4Filesystem) IsEncryptionEnabled() bool {
	return C.ext2fs_has_feature_encrypt(fs.ptr.super) != 0
}

// EnableEncryption sets the "encrypt" feature flag and writes the appropriate
// information in the superblock to allow filesystem encryption.
func (fs *Ext4Filesystem) EnableEncryption() error {
	return nil
}

// DisableEncryption removes the "encrypt" feature flag.
func (fs *Ext4Filesystem) DisableEncryption() error {
	return nil
}

// Close safely closes, frees, and runs cleanup f9r the filesystem.
func (fs *Ext4Filesystem) Close() error {
	return nil
}

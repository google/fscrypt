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
	"unsafe"
)

// isExt4EncryptionEnabled returns true if the provided ext4 filesystem (as a
// path to a device or mountpoint) has the encrypt feature flag enabled.
func isExt4EncryptionEnabled(path string) bool {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var fs C.ext2_filsys
	ret := C.ext2fs_open(cPath, 0, 0, 0, C.unix_io_manager, &fs)
	if ret != 0 {
		panic(fmt.Errorf("Got error code %v when opening %s", ret, path))
	}

	hasEncryption := C.ext2fs_has_feature_encrypt(fs.super)
	return hasEncryption != 0
}

// enableExt4Encryption enables encryption on the filesystem at the specified
// path.

// disableExt4Encryption disables encryption on the filesystem at the specified
// path. Note that this operation is not supported and can cause data loss.

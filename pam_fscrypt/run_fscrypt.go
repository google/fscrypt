/*
 * run_fscrypt.go - Helpers for running functions in the PAM module.
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
#cgo LDFLAGS: -lpam -fPIC

#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
*/
import "C"
import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"path/filepath"
	"runtime/debug"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/pam"
	"github.com/google/fscrypt/util"
)

const (
	// countDirectory is in a tmpfs filesystem so it will reset on reboot.
	countDirectory = "/run/fscrypt"
	// count files should only be readable and writable by root
	countDirectoryPermissions = 0700
	countFilePermissions      = 0600
	countFileFormat           = "%d\n"
)

// PamFunc is used to define the various actions in the PAM module.
type PamFunc struct {
	// Name of the function being executed
	name string
	// Go implementation of this function
	impl func(handle *pam.Handle, args map[string]bool) error
}

// Run is used to convert between the Go functions and exported C funcs.
func (f *PamFunc) Run(pamh unsafe.Pointer, argc C.int, argv **C.char) (ret C.int) {
	args := parseArgs(argc, argv)
	errorWriter := setupLogging(args)

	// Log any panics to the errorWriter
	defer func() {
		if r := recover(); r != nil {
			ret = C.PAM_SERVICE_ERR
			fmt.Fprintf(errorWriter,
				"%s(%v) panicked: %s\nPlease open a bug.\n%s",
				f.name, args, r, debug.Stack())
		}
	}()

	log.Printf("%s(%v) starting", f.name, args)
	handle, err := pam.NewHandle(pamh)
	if err == nil {
		err = f.impl(handle, args)
	}
	if err != nil {
		fmt.Fprintf(errorWriter, "%s(%v) failed: %s", f.name, args, err)
		return C.PAM_SERVICE_ERR
	}
	log.Printf("%s(%v) succeeded", f.name, args)
	return C.PAM_SUCCESS
}

// parseArgs takes a list of C arguments into a PAM function and returns a map
// where a key has a value of true if it appears in the argument list.
func parseArgs(argc C.int, argv **C.char) map[string]bool {
	args := make(map[string]bool)
	if argc == 0 || argv == nil {
		return args
	}
	for _, cString := range util.PointerSlice(unsafe.Pointer(argv))[:argc] {
		args[C.GoString((*C.char)(cString))] = true
	}
	return args
}

// setupLogging directs turns off standard logging (or redirects it to debug
// syslog if the "debug" argument is passed) and returns a writer to the error
// syslog.
func setupLogging(args map[string]bool) io.Writer {
	log.SetFlags(0) // Syslog already includes time data itself
	log.SetOutput(ioutil.Discard)
	if args[debugFlag] {
		debugWriter, err := syslog.New(syslog.LOG_DEBUG, moduleName)
		if err == nil {
			log.SetOutput(debugWriter)
		}
	}

	errorWriter, err := syslog.New(syslog.LOG_ERR, moduleName)
	if err != nil {
		return ioutil.Discard
	}
	return errorWriter
}

// loginProtector returns the login protector corresponding to the PAM_USER if
// one exists. This protector descriptor (if found) will be cached in the pam
// data, under descriptorLabel.
func loginProtector(handle *pam.Handle) (*actions.Protector, error) {
	ctx, err := actions.NewContextFromMountpoint(actions.LoginProtectorMountpoint,
		handle.PamUser)
	if err != nil {
		return nil, err
	}
	// Ensure that pam_fscrypt only processes metadata files owned by the
	// user or root, even if the user is root themselves.  (Normally, when
	// fscrypt is run as root it is allowed to process all metadata files.
	// This implements stricter behavior for pam_fscrypt.)
	if !ctx.Config.GetAllowCrossUserMetadata() {
		ctx.TrustedUser = handle.PamUser
	}

	// Find the user's PAM protector.
	options, err := ctx.ProtectorOptions()
	if err != nil {
		return nil, err
	}
	uid := int64(util.AtoiOrPanic(handle.PamUser.Uid))
	for _, option := range options {
		if option.Source() == metadata.SourceType_pam_passphrase && option.UID() == uid {
			return actions.GetProtectorFromOption(ctx, option)
		}
	}
	return nil, errors.Errorf("no PAM protector for UID=%d on %q", uid, ctx.Mount.Path)
}

// policiesUsingProtector searches all the mountpoints for any policies
// protected with the specified protector.
func policiesUsingProtector(protector *actions.Protector) []*actions.Policy {
	mounts, err := filesystem.AllFilesystems()
	if err != nil {
		log.Print(err)
		return nil
	}

	var policies []*actions.Policy
	for _, mount := range mounts {
		// Skip mountpoints that do not use the protector.
		if _, _, err := mount.GetProtector(protector.Descriptor(),
			protector.Context.TrustedUser); err != nil {
			continue
		}
		policyDescriptors, err := mount.ListPolicies(protector.Context.TrustedUser)
		if err != nil {
			log.Printf("listing policies: %s", err)
			continue
		}

		// Clone context but modify the mountpoint
		ctx := *protector.Context
		ctx.Mount = mount
		for _, policyDescriptor := range policyDescriptors {
			policy, err := actions.GetPolicy(&ctx, policyDescriptor)
			if err != nil {
				log.Printf("reading policy: %s", err)
				continue
			}

			if policy.UsesProtector(protector) {
				policies = append(policies, policy)
			}
		}
	}
	return policies
}

// AdjustCount changes the session count for the pam user by the specified
// amount. If the count file does not exist, create it as if it had a count of
// zero. If the adjustment would bring the count below zero, the count is set to
// zero. The value of the new count is returned. Requires root privileges.
func AdjustCount(handle *pam.Handle, delta int) (int, error) {
	// Make sure the directory exists
	if err := os.MkdirAll(countDirectory, countDirectoryPermissions); err != nil {
		return 0, err
	}

	path := filepath.Join(countDirectory, handle.PamUser.Uid+".count")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, countFilePermissions)
	if err != nil {
		return 0, err
	}
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return 0, err
	}
	defer file.Close()

	newCount := util.MaxInt(getCount(file)+delta, 0)
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	if _, err = fmt.Fprintf(file, countFileFormat, newCount); err != nil {
		return 0, err
	}

	log.Printf("Session count for UID=%s updated to %d", handle.PamUser.Uid, newCount)
	return newCount, nil
}

// Returns the count in the file (or zero if the count cannot be read).
func getCount(file *os.File) int {
	var count int
	if _, err := fmt.Fscanf(file, countFileFormat, &count); err != nil {
		return 0
	}
	return count
}

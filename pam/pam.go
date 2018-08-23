/*
 * pam.go - Utility functions for interfacing with the PAM libraries.
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

package pam

/*
#cgo LDFLAGS: -lpam
#include "pam.h"

#include <pwd.h>
#include <stdlib.h>
#include <security/pam_modules.h>
*/
import "C"
import (
	"errors"
	"log"
	"os/user"
	"unsafe"

	"github.com/google/fscrypt/security"
)

// Handle wraps the C pam_handle_t type. This is used from within modules.
type Handle struct {
	handle    *C.pam_handle_t
	status    C.int
	origPrivs *security.Privileges
	// PamUser is the user for whom the PAM module is running.
	PamUser *user.User
}

// NewHandle creates a Handle from a raw pointer.
func NewHandle(pamh unsafe.Pointer) (*Handle, error) {
	var err error
	h := &Handle{
		handle: (*C.pam_handle_t)(pamh),
		status: C.PAM_SUCCESS,
	}

	var pamUsername *C.char
	h.status = C.pam_get_user(h.handle, &pamUsername, nil)
	if err = h.err(); err != nil {
		return nil, err
	}

	h.PamUser, err = user.Lookup(C.GoString(pamUsername))
	return h, err
}

func (h *Handle) setData(name string, data unsafe.Pointer, cleanup C.CleanupFunc) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	h.status = C.pam_set_data(h.handle, cName, data, cleanup)
	return h.err()
}

func (h *Handle) getData(name string) (unsafe.Pointer, error) {
	var data unsafe.Pointer
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	h.status = C.pam_get_data(h.handle, cName, &data)
	return data, h.err()
}

// ClearData remotes the PAM data with the specified name.
func (h *Handle) ClearData(name string) error {
	return h.setData(name, unsafe.Pointer(C.CString("")), C.CleanupFunc(C.freeData))
}

// SetSecret sets a copy of the C string secret into the PAM data with the
// specified name. This copy will be held in locked memory until this PAM data
// is cleared.
func (h *Handle) SetSecret(name string, secret unsafe.Pointer) error {
	return h.setData(name, C.copyIntoSecret(secret), C.CleanupFunc(C.freeSecret))
}

// GetSecret returns a pointer to the C string PAM data with the specified name.
// This a pointer directory to the data, so it shouldn't be modified. It should
// have been previously set with SetSecret().
func (h *Handle) GetSecret(name string) (unsafe.Pointer, error) {
	return h.getData(name)
}

// SetString sets a string value for the PAM data with the specified name.
func (h *Handle) SetString(name string, s string) error {
	return h.setData(name, unsafe.Pointer(C.CString(s)), C.CleanupFunc(C.freeData))
}

// GetString gets a string value for the PAM data with the specified name. It
// should have been previously set with SetString().
func (h *Handle) GetString(name string) (string, error) {
	data, err := h.getData(name)
	if err != nil {
		return "", err
	}
	return C.GoString((*C.char)(data)), nil
}

// GetItem retrieves a PAM information item. This is a pointer directly to the
// data, so it shouldn't be modified.
func (h *Handle) GetItem(i Item) (unsafe.Pointer, error) {
	var data unsafe.Pointer
	h.status = C.pam_get_item(h.handle, C.int(i), &data)
	if err := h.err(); err != nil {
		return nil, err
	}
	if data == nil {
		return nil, errors.New("item not found")
	}
	return data, nil
}

// StartAsPamUser sets the effective privileges to that of the PAM user, and
// configures the PAM user's keyrings to be properly linked.
func (h *Handle) StartAsPamUser() error {
	if _, err := security.UserKeyringID(h.PamUser, true); err != nil {
		log.Printf("Setting up keyrings in PAM: %v", err)
	}
	userPrivs, err := security.UserPrivileges(h.PamUser)
	if err != nil {
		return err
	}
	if h.origPrivs, err = security.ProcessPrivileges(); err != nil {
		return err
	}
	return security.SetProcessPrivileges(userPrivs)
}

// StopAsPamUser restores the original privileges that were running the
// PAM module (this is usually root).
func (h *Handle) StopAsPamUser() error {
	err := security.SetProcessPrivileges(h.origPrivs)
	if err != nil {
		log.Print(err)
	}
	return err
}

func (h *Handle) err() error {
	if h.status == C.PAM_SUCCESS {
		return nil
	}
	s := C.GoString(C.pam_strerror(h.handle, C.int(h.status)))
	return errors.New(s)
}

// Transaction represents a wrapped pam_handle_t type created with pam_start
// form an application.
type Transaction Handle

// Start initializes a pam Transaction. End() should be called after the
// Transaction is no longer needed.
func Start(service, username string) (*Transaction, error) {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cUsername := C.CString(username)
	defer C.free(unsafe.Pointer(cUsername))

	t := &Transaction{
		handle: nil,
		status: C.PAM_SUCCESS,
	}
	t.status = C.pam_start(
		cService,
		cUsername,
		C.goConv,
		&t.handle)
	return t, (*Handle)(t).err()
}

// End finalizes a pam Transaction with pam_end().
func (t *Transaction) End() {
	C.pam_end(t.handle, t.status)
}

// Authenticate returns a boolean indicating if the user authenticated correctly
// or not. If the authentication check did not complete, an error is returned.
func (t *Transaction) Authenticate(quiet bool) (bool, error) {
	var flags C.int = C.PAM_DISALLOW_NULL_AUTHTOK
	if quiet {
		flags |= C.PAM_SILENT
	}
	t.status = C.pam_authenticate(t.handle, flags)
	if t.status == C.PAM_AUTH_ERR {
		return false, nil
	}
	return true, (*Handle)(t).err()
}

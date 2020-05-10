/*
 * pam.h - Functions to let us call into libpam from Go.
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

#ifndef FSCRYPT_PAM_H
#define FSCRYPT_PAM_H

#include <security/pam_appl.h>

// Conversation that will call back into Go code when appropriate.
extern const struct pam_conv *goConv;

// CleaupFuncs are used to cleanup specific PAM data.
typedef void (*CleanupFunc)(pam_handle_t *pamh, void *data, int error_status);

// CleaupFunc that calls free() on data.
void freeData(pam_handle_t *pamh, void *data, int error_status);

// CleaupFunc that frees each item in a null terminated array of pointers and
// then frees the array itself.
void freeArray(pam_handle_t *pamh, void **array, int error_status);

// Creates a copy of a C string, which resides in a locked buffer.
void *copyIntoSecret(void *data);

// CleaupFunc that Zeros wipes a C string and unlocks and frees its memory.
void freeSecret(pam_handle_t *pamh, char *data, int error_status);

#endif  // FSCRYPT_PAM_H

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

// fscrypt_service is the display name of the service requesting the passphrase.
const char* fscrypt_service;

// pam_init initializes the pam_conv structure for use with our Go callbacks.
void pam_init(struct pam_conv* conv);

#endif

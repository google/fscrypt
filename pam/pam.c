/*
 * pam.c - Functions to let us call into libpam from Go.
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

#include "pam.h"

#include <stdio.h>
#include <stdlib.h>

#include "_cgo_export.h"  // for pamInput callback

const char* fscrypt_service = "fscrypt";

static int pam_conv(int num_msg, const struct pam_message** msg,
                    struct pam_response** resp, void* appdata_ptr) {
  if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) {
    return PAM_CONV_ERR;
  }

  // Allocate the response table with num_msg entries.
  *resp = calloc(num_msg, sizeof **resp);
  if (!*resp) {
    return PAM_BUF_ERR;
  }

  // Check each message to see if we need to run a callback.
  char* callback_msg = NULL;
  char* callback_resp = NULL;
  int i;
  for (i = 0; i < num_msg; ++i) {
    callback_msg = (char*)msg[i]->msg;

    // We run our input callback if the style tells us we need data. Otherwise,
    // we just print the error messages or text info to standard output.
    switch (msg[i]->msg_style) {
      case PAM_PROMPT_ECHO_OFF:
        callback_resp = pamInput(callback_msg);
        break;
      case PAM_PROMPT_ECHO_ON:
        // We should never have a request for non-secret data
        unexpectedMessage(callback_msg);
        callback_resp = NULL;
        break;
      case PAM_ERROR_MSG:
      case PAM_TEXT_INFO:
        printf("%s\n", callback_msg);
        continue;
    }

    if (!callback_resp) {
      // If the callback failed, free each nonempty response in the response
      // table and the response table itself.
      while (--i >= 0) {
        free((*resp)[i].resp);
      }
      free(*resp);
      return PAM_CONV_ERR;
    }

    (*resp)[i].resp = callback_resp;
  }
  return PAM_SUCCESS;
}

void pam_init(struct pam_conv* conv) { conv->conv = pam_conv; }

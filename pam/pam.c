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
#include <string.h>

#include <security/pam_appl.h>
#include <sys/mman.h>  // mlock/munlock

#include "_cgo_export.h"  // for input callbacks

static int conversation(int num_msg, const struct pam_message** msg,
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
        callback_resp = passphraseInput(callback_msg);
        break;
      case PAM_PROMPT_ECHO_ON:
        callback_resp = userInput(callback_msg);
        break;
      case PAM_ERROR_MSG:
      case PAM_TEXT_INFO:
        fprintf(stderr, "%s\n", callback_msg);
        continue;
    }

    if (!callback_resp) {
      // If the callback failed, free each nonempty response in the response
      // table and the response table itself.
      while (--i >= 0) {
        free((*resp)[i].resp);
      }
      free(*resp);
      *resp = NULL;
      return PAM_CONV_ERR;
    }

    (*resp)[i].resp = callback_resp;
  }

  return PAM_SUCCESS;
}

static const struct pam_conv conv = {conversation, NULL};
const struct pam_conv* goConv = &conv;

void freeData(pam_handle_t* pamh, void* data, int error_status) { free(data); }

void freeArray(pam_handle_t* pamh, void** array, int error_status) {
  int i;
  for (i = 0; array[i]; ++i) {
    free(array[i]);
  }
  free(array);
}

void* copyIntoSecret(void* data) {
  size_t size = strlen(data) + 1;  // include null terminator
  void* copy = malloc(size);
  mlock(copy, size);
  memcpy(copy, data, size);
  return copy;
}

void freeSecret(pam_handle_t* pamh, char* data, int error_status) {
  size_t size = strlen(data) + 1;  // Include null terminator
  // Use volitile function pointer to actually clear the memory.
  static void* (*const volatile memset_sec)(void*, int, size_t) = &memset;
  memset_sec(data, 0, size);
  munlock(data, size);
  free(data);
}

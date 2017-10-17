/*
 * errors.go - Common errors and error handling
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

package cmd

import (
	"fmt"
	"os"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/util"
)

// Common errors used across tools
var (
	ErrUnknownVersion = errors.New("unknown version (missing version tag)")
	ErrCanceled       = errors.New("operation canceled by user")
	ErrMustForce      = errors.New("operation must be forced")
	ErrNotRoot        = errors.New("operation must be run as root")
)

// Error return codes
var (
	FailureCode      = 1
	UsageFailureCode = 2
)

// UsageError is an error type used to denote that a command was incorrectly
// specified. Returning this type from an Action will cause print the command's
// usage to os.Stdout before exiting with UsageFailureCode.
type UsageError string

func (u UsageError) Error() string { return string(u) }

// CheckExpectedArgs returns a UsageError if the number of arguments in the
// context does not match expectedArgs. If atMost is set, the number of args
// is allowed to be less than expectedArgs.
func CheckExpectedArgs(ctx *Context, expectedArgs int, atMost bool) error {
	// Check the number of arguments and build the message.
	nArgs := len(ctx.Args)
	message := "expected"
	if atMost {
		if nArgs <= expectedArgs {
			return nil
		}
		message += " at most"
	} else {
		if nArgs == expectedArgs {
			return nil
		}
	}
	// We have the wrong number of arguments
	message += fmt.Sprintf(" %s, got %s",
		Pluralize(expectedArgs, "argument"),
		Pluralize(nArgs, "argument"))
	return UsageError(message)
}

// CheckIfRoot returns an error if the current user is not the root user.
func CheckIfRoot() error {
	if id := util.CurrentUserID(); id != 0 {
		return errors.Wrapf(ErrNotRoot, "user %s", util.GetUser(id).Username)
	}
	return nil
}

// CheckRequiredFlags returns a UsageError if all of the required flags are not
// set. Only StringFlags are currently supported.
func CheckRequiredFlags(flags []*StringFlag) error {
	for _, flag := range flags {
		if flag.Value == "" {
			return UsageError(fmt.Sprintf("required flag %s not set", flag))
		}
	}
	return nil
}

// processError TODO(joerichey)
func (ctx *Context) processError(err error) {
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "%s: %s\n", ctx.FullName(), err)
	// Usage Errors should print the usage information
	if _, ok := err.(UsageError); ok {
		ExecuteTemplate(os.Stderr, TemplateUsage, ctx)
		os.Exit(UsageFailureCode)
		return
	}

	// Errors with a help text should print it out.
	if helpText := ctx.getHelpText(err); helpText != "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, WrapText(helpText, 0))
	}
	os.Exit(FailureCode)
	return
}

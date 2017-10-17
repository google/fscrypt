/*
 * status.go - File which contains the functions for outputting the status of
 * fscrypt, a filesystem, or a directory.
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

import (
	"fmt"
	"io"
	"log"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/cmd"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
)

// Creates a writer which correctly aligns tabs with the specified header.
// Must call Flush() when done.
func makeTableWriter(w io.Writer, header string) *tabwriter.Writer {
	tableWriter := tabwriter.NewWriter(w, 0, indentLength, indentLength, ' ', 0)
	fmt.Fprintln(tableWriter, header)
	return tableWriter
}

// encryptionStatus will be printed in the ENCRYPTION column. An empty string
// indicates the filesystem should not be printed.
func encryptionStatus(err error) string {
	switch errors.Cause(err) {
	case nil:
		return "supported"
	case metadata.ErrEncryptionNotEnabled:
		return "not enabled"
	case metadata.ErrEncryptionNotSupported:
		return "not supported"
	default:
		// Unknown error regarding support
		return ""
	}
}

func yesNoString(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// writeGlobalStatus prints all the filesystem that use (or could use) fscrypt.
func writeGlobalStatus() error {
	mounts, err := filesystem.AllFilesystems()
	if err != nil {
		return err
	}

	supportCount := 0
	useCount := 0

	t := makeTableWriter(cmd.Output, "MOUNTPOINT\tDEVICE\tFILESYSTEM\tENCRYPTION\tFSCRYPT")
	for _, mount := range mounts {
		// Only print mountpoints backed by devices or using fscrypt.
		usingFscrypt := mount.CheckSetup() == nil
		if !usingFscrypt && mount.Device == "" {
			continue
		}

		// Only print a mountpoint if we can determine its support.
		supportErr := mount.CheckSupport()
		supportString := encryptionStatus(supportErr)
		if supportString == "" {
			log.Print(supportErr)
			continue
		}

		fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\n", mount.Path, mount.Device, mount.Filesystem,
			supportString, yesNoString(usingFscrypt))

		if supportErr == nil {
			supportCount++
		}
		if usingFscrypt {
			useCount++
		}
	}

	fmt.Fprintf(cmd.Output, "filesystems supporting encryption: %d\n", supportCount)
	fmt.Fprintf(cmd.Output, "filesystems with fscrypt metadata: %d\n\n", useCount)
	return t.Flush()
}

// writeOptions writes a table of the status for a slice of protector options.
func writeOptions(options []*actions.ProtectorOption) {
	t := makeTableWriter(cmd.Output, "PROTECTOR\tLINKED\tDESCRIPTION")
	for _, option := range options {
		if option.LoadError != nil {
			fmt.Fprintf(t, "%s\t\t[%s]\n", option.Descriptor(), option.LoadError)
			continue
		}

		// For linked protectors, indicate which filesystem.
		isLinked := option.LinkedMount != nil
		linkedText := yesNoString(isLinked)
		if isLinked {
			linkedText += fmt.Sprintf(" (%s)", option.LinkedMount.Path)
		}
		fmt.Fprintf(t, "%s\t%s\t%s\n", option.Descriptor(), linkedText,
			formatInfo(option.ProtectorInfo))
	}
	t.Flush()
}

func writeFilesystemStatus(ctx *actions.Context) error {
	options, err := ctx.ProtectorOptions()
	if err != nil {
		return err
	}

	policyDescriptors, err := ctx.Mount.ListPolicies()
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "%s filesystem %q has %s and %s\n\n", ctx.Mount.Filesystem, ctx.Mount.Path,
		pluralize(len(options), "protector"), pluralize(len(policyDescriptors), "policy"))

	if len(options) > 0 {
		writeOptions(options)
	}

	if len(policyDescriptors) == 0 {
		return nil
	}

	fmt.Fprintln(cmd.Output)
	t := makeTableWriter(cmd.Output, "POLICY\tUNLOCKED\tPROTECTORS")
	for _, descriptor := range policyDescriptors {
		policy, err := actions.GetPolicy(ctx, descriptor)
		if err != nil {
			fmt.Fprintf(t, "%s\t\t[%s]\n", descriptor, err)
			continue
		}

		fmt.Fprintf(t, "%s\t%s\t%s\n", descriptor, yesNoString(policy.IsProvisioned()),
			strings.Join(policy.ProtectorDescriptors(), ", "))
	}
	return t.Flush()
}

func writePathStatus(path string) error {
	ctx, err := actions.NewContextFromPath(path, nil)
	if err != nil {
		return err
	}
	policy, err := actions.GetPolicyFromPath(ctx, path)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.Output, "%q is encrypted with fscrypt.\n", path)
	fmt.Fprintln(cmd.Output)
	fmt.Fprintf(cmd.Output, "Policy:   %s\n", policy.Descriptor())
	fmt.Fprintf(cmd.Output, "Unlocked: %s\n", yesNoString(policy.IsProvisioned()))
	fmt.Fprintln(cmd.Output)

	options := policy.ProtectorOptions()
	fmt.Fprintf(cmd.Output, "Protected with %s:\n", pluralize(len(options), "protector"))
	writeOptions(cmd.Output, options)
	return nil
}

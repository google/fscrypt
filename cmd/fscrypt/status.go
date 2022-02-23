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

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/keyring"
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
	if err == nil {
		return "supported"
	}
	switch err.(type) {
	case *filesystem.ErrEncryptionNotEnabled:
		return "not enabled"
	case *filesystem.ErrEncryptionNotSupported:
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

func policyUnlockedStatus(policy *actions.Policy, path string) string {
	status := policy.GetProvisioningStatus()

	// Due to a limitation in the old kernel API for fscrypt, for v1
	// policies using the user keyring that are incompletely locked or are
	// unlocked by another user, we'll get KeyAbsent.  If we have a
	// directory path, use a heuristic to try to detect these cases.
	if status == keyring.KeyAbsent && policy.NeedsUserKeyring() &&
		path != "" && isDirUnlockedHeuristic(path) {
		return "Partially (incompletely locked, or unlocked by another user)"
	}

	switch status {
	case keyring.KeyPresent, keyring.KeyPresentButOnlyOtherUsers:
		return "Yes"
	case keyring.KeyAbsent:
		return "No"
	case keyring.KeyAbsentButFilesBusy:
		return "Partially (incompletely locked)"
	default:
		return "Unknown"
	}
}

// writeGlobalStatus prints all the filesystems that use (or could use) fscrypt.
func writeGlobalStatus(w io.Writer) error {
	mounts, err := filesystem.AllFilesystems()
	if err != nil {
		return err
	}

	supportCount := 0
	useCount := 0

	t := makeTableWriter(w, "MOUNTPOINT\tDEVICE\tFILESYSTEM\tENCRYPTION\tFSCRYPT")
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

		fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\n",
			filesystem.EscapeString(mount.Path),
			filesystem.EscapeString(mount.Device),
			filesystem.EscapeString(mount.FilesystemType),
			supportString, yesNoString(usingFscrypt))

		if supportErr == nil {
			supportCount++
		}
		if usingFscrypt {
			useCount++
		}
	}

	fmt.Fprintf(w, "filesystems supporting encryption: %d\n", supportCount)
	fmt.Fprintf(w, "filesystems with fscrypt metadata: %d\n\n", useCount)
	return t.Flush()
}

// writeOptions writes a table of the status for a slice of protector options.
func writeOptions(w io.Writer, options []*actions.ProtectorOption) {
	t := makeTableWriter(w, "PROTECTOR\tLINKED\tDESCRIPTION")
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

func writeFilesystemStatus(w io.Writer, ctx *actions.Context) error {
	options, err := ctx.ProtectorOptions()
	if err != nil {
		return err
	}

	policyDescriptors, err := ctx.Mount.ListPolicies(ctx.TrustedUser)
	if err != nil {
		return err
	}

	filterDescription := ""
	if ctx.TrustedUser != nil {
		filterDescription = fmt.Sprintf(" (only including ones owned by %s or root)", ctx.TrustedUser.Username)
	}
	fmt.Fprintf(w, "%s filesystem %q has %s and %s%s.\n", ctx.Mount.FilesystemType,
		ctx.Mount.Path, pluralize(len(options), "protector"),
		pluralize(len(policyDescriptors), "policy"), filterDescription)
	if setupMode, user, err := ctx.Mount.GetSetupMode(); err == nil {
		switch setupMode {
		case filesystem.WorldWritable:
			fmt.Fprintf(w, "All users can create fscrypt metadata on this filesystem.\n")
		case filesystem.SingleUserWritable:
			fmt.Fprintf(w, "Only %s can create fscrypt metadata on this filesystem.\n", user.Username)
		}
	}
	fmt.Fprintf(w, "\n")

	if len(options) > 0 {
		writeOptions(w, options)
	}

	if len(policyDescriptors) == 0 {
		return nil
	}

	fmt.Fprintln(w)
	t := makeTableWriter(w, "POLICY\tUNLOCKED\tPROTECTORS")
	for _, descriptor := range policyDescriptors {
		policy, err := actions.GetPolicy(ctx, descriptor)
		if err != nil {
			fmt.Fprintf(t, "%s\t\t[%s]\n", descriptor, err)
			continue
		}

		fmt.Fprintf(t, "%s\t%s\t%s\n", descriptor,
			policyUnlockedStatus(policy, ""),
			strings.Join(policy.ProtectorDescriptors(), ", "))
	}
	return t.Flush()
}

func writePathStatus(w io.Writer, path string) error {
	ctx, err := actions.NewContextFromPath(path, nil)
	if err != nil {
		return err
	}
	policy, err := actions.GetPolicyFromPath(ctx, path)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "%q is encrypted with fscrypt.\n", path)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Policy:   %s\n", policy.Descriptor())
	fmt.Fprintf(w, "Options:  %s\n", policy.Options())
	fmt.Fprintf(w, "Unlocked: %s\n", policyUnlockedStatus(policy, path))
	fmt.Fprintln(w)

	options := policy.ProtectorOptions()
	fmt.Fprintf(w, "Protected with %s:\n", pluralize(len(options), "protector"))
	writeOptions(w, options)
	return nil
}

/*
 * flags.go - File which contains all the flags used by the application. This
 * includes both global flags and command specific flags. When applicable, it
 * also includes the default values.
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
	"flag"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/urfave/cli"

	"github.com/google/fscrypt/actions"
)

// We define the types boolFlag, durationFlag, and stringFlag here instead of
// using those present in urfave/cli because we need them to conform to the
// prettyFlag interface (in format.go). The Getters just get the corresponding
// variables, String() just uses longDisplay, and Apply just sets the
// corresponding type of flag.
type boolFlag struct {
	Name    string
	Usage   string
	Default bool
	Value   bool
}

func (b *boolFlag) GetName() string    { return b.Name }
func (b *boolFlag) GetArgName() string { return "" }
func (b *boolFlag) GetUsage() string   { return b.Usage }

func (b *boolFlag) String() string {
	if b.Default == false {
		return longDisplay(b)
	}
	return longDisplay(b, strconv.FormatBool(b.Default))
}

func (b *boolFlag) Apply(set *flag.FlagSet) {
	set.BoolVar(&b.Value, b.Name, b.Default, b.Usage)
}

type durationFlag struct {
	Name    string
	ArgName string
	Usage   string
	Default time.Duration
	Value   time.Duration
}

func (d *durationFlag) GetName() string    { return d.Name }
func (d *durationFlag) GetArgName() string { return d.ArgName }
func (d *durationFlag) GetUsage() string   { return d.Usage }

func (d *durationFlag) String() string {
	if d.Default == 0 {
		return longDisplay(d)
	}
	return longDisplay(d, d.Value.String())
}

func (d *durationFlag) Apply(set *flag.FlagSet) {
	set.DurationVar(&d.Value, d.Name, d.Default, d.Usage)
}

type stringFlag struct {
	Name    string
	ArgName string
	Usage   string
	Default string
	Value   string
}

func (s *stringFlag) GetName() string    { return s.Name }
func (s *stringFlag) GetArgName() string { return s.ArgName }
func (s *stringFlag) GetUsage() string   { return s.Usage }

func (s *stringFlag) String() string {
	if s.Default == "" {
		return longDisplay(s)
	}
	return longDisplay(s, strconv.Quote(s.Default))
}

func (s *stringFlag) Apply(set *flag.FlagSet) {
	set.StringVar(&s.Value, s.Name, s.Default, s.Usage)
}

var (
	// allFlags contains every defined flag (used for formatting).
	// UPDATE THIS ARRAY WHEN ADDING NEW FLAGS!!!
	// TODO(joerichey) add presubmit rule to enforce this
	allFlags = []prettyFlag{helpFlag, versionFlag, verboseFlag, quietFlag,
		forceFlag, legacyFlag, skipUnlockFlag, timeTargetFlag,
		sourceFlag, nameFlag, keyFileFlag, protectorFlag,
		unlockWithFlag, policyFlag}
	// universalFlags contains flags that should be on every command
	universalFlags = []cli.Flag{verboseFlag, quietFlag, helpFlag}
)

// Bool flags: used to switch some behavior on or off
var (
	helpFlag = &boolFlag{
		Name:  "help",
		Usage: `Prints help screen for commands and subcommands.`,
	}
	versionFlag = &boolFlag{
		Name:  "version",
		Usage: `Prints version and license information.`,
	}
	verboseFlag = &boolFlag{
		Name:  "verbose",
		Usage: `Prints additional debug messages to standard output.`,
	}
	quietFlag = &boolFlag{
		Name: "quiet",
		Usage: `Prints nothing to standard output except for errors.
			Selects the default for any options that would normally
			show a prompt.`,
	}
	forceFlag = &boolFlag{
		Name: "force",
		Usage: fmt.Sprintf(`Suppresses all confirmation prompts and
			warnings, causing any action to automatically proceed.
			WARNING: This bypasses confirmations for protective
			operations, use with care.`),
	}
	legacyFlag = &boolFlag{
		Name: "legacy",
		Usage: `Allow for support of older kernels with ext4 (before
			v4.8) and F2FS (before v4.6) filesystems.`,
		Default: true,
	}
	skipUnlockFlag = &boolFlag{
		Name: "skip-unlock",
		Usage: `Leave the directory in a locked state after setup.
			"fscrypt unlock" will need to be run in order to use the
			directory.`,
	}
)

// Option flags: used to specify options instead of being prompted for them
var (
	timeTargetFlag = &durationFlag{
		Name:    "time",
		ArgName: "TIME",
		Usage: `Set the global options so that passphrase hashing takes
			TIME long. TIME should be formatted as a sequence of
			decimal numbers, each with optional fraction and a unit
			suffix, such as "300ms", "1.5s" or "2h45m". Valid time
			units are "ms", "s", "m", and "h".`,
		Default: 1 * time.Second,
	}
	sourceFlag = &stringFlag{
		Name:    "source",
		ArgName: "SOURCE",
		Usage: fmt.Sprintf(`New protectors will have type SOURCE. SOURCE
			can be one of pam_passphrase, custom_passphrase, or
			raw_key. If not specified, the user will be prompted for
			the source, with a default pulled from %s.`,
			actions.ConfigFileLocation),
	}
	nameFlag = &stringFlag{
		Name:    "name",
		ArgName: "PROTECTOR_NAME",
		Usage: `New custom_passphrase and raw_key protectors will be
			named PROTECTOR_NAME. If not specified, the user will be
			prompted for a name.`,
	}
	keyFileFlag = &stringFlag{
		Name:    "key",
		ArgName: "FILE",
		Usage: `Use the contents of FILE as the wrapping key when
			creating or unlocking raw_key protectors. FILE should be
			formatted as raw binary and should be exactly 32 bytes
			long.`,
	}
	protectorFlag = &stringFlag{
		Name:    "protector",
		ArgName: "MOUNTPOINT:ID",
		Usage: `Specify an existing protector on filesystem MOUNTPOINT
			with protector descriptor ID which should be used in the
			command.`,
	}
	unlockWithFlag = &stringFlag{
		Name:    "unlock-with",
		ArgName: "MOUNTPOINT:ID",
		Usage: `Specify an existing protector on filesystem MOUNTPOINT
			with protector descriptor ID which should be used to
			unlock a policy (usually specified with --policy). This
			flag is only useful if a policy is protected with
			multiple protectors. If not specified, the user will be
			prompted for a protector.`,
	}
	policyFlag = &stringFlag{
		Name:    "policy",
		ArgName: "MOUNTPOINT:ID",
		Usage: `Specify an existing policy on filesystem MOUNTPOINT with
			key descriptor ID which should be used in the command.`,
	}
)

// The first group is optional and corresponds to the mountpoint. The second
// group is required and corresponds to the descriptor.
var idFlagRegex = regexp.MustCompile("^([[:print:]]+):([[:alnum:]]+)$")

// parseMetadataFlag takes the value of either protectorFlag or policyFlag
// formatted as MOUNTPOINT:DESCRIPTOR, and returns a context for the mountpoint
// and a string for the descriptor.
func parseMetadataFlag(flagValue string) (*actions.Context, string, error) {
	matches := idFlagRegex.FindStringSubmatch(flagValue)
	if matches == nil {
		err := fmt.Errorf("flag value %q does not have format %s", flagValue, mountpointIDArg)
		return nil, "", err
	}

	mountpoint := matches[1]
	descriptor := matches[2]
	log.Printf("parsed flag: mountpoint=%q descriptor=%s", mountpoint, descriptor)

	ctx, err := actions.NewContextFromMountpoint(mountpoint)
	return ctx, descriptor, err
}

// getProtectorFromFlag gets an existing locked protector from protectorFlag.
func getProtectorFromFlag(flagValue string) (*actions.Protector, error) {
	ctx, descriptor, err := parseMetadataFlag(flagValue)
	if err != nil {
		return nil, err
	}
	return actions.GetProtector(ctx, descriptor)
}

// getPolicyFromFlag gets an existing locked policy from policyFlag.
func getPolicyFromFlag(flagValue string) (*actions.Policy, error) {
	ctx, descriptor, err := parseMetadataFlag(flagValue)
	if err != nil {
		return nil, err
	}
	return actions.GetPolicy(ctx, descriptor)
}

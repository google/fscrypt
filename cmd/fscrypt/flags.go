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
	"os/user"
	"regexp"
	"strconv"
	"time"

	"github.com/urfave/cli"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/util"
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
	if !b.Default {
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
		forceFlag, skipUnlockFlag, timeTargetFlag,
		sourceFlag, nameFlag, keyFileFlag, protectorFlag,
		unlockWithFlag, policyFlag, allUsersFlag, noRecoveryFlag}
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
		Usage: `Prints version information.`,
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
	skipUnlockFlag = &boolFlag{
		Name: "skip-unlock",
		Usage: `Leave the directory in a locked state after setup.
			"fscrypt unlock" will need to be run in order to use the
			directory.`,
	}
	dropCachesFlag = &boolFlag{
		Name: "drop-caches",
		Usage: `After removing the key(s) from the keyring, drop the
			kernel's filesystem caches if needed. Without this flag,
			files encrypted with v1 encryption policies may still be
			accessible. This flag is not needed for v2 encryption
			policies. This flag, if actually needed, requires root
			privileges.`,
		Default: true,
	}
	allUsersFlag = &boolFlag{
		Name: "all-users",
		Usage: `Lock the directory no matter which user(s) have unlocked
			it. Requires root privileges. This flag is only
			necessary if the directory was unlocked by a user
			different from the one you're locking it as. This flag
			is only implemented for v2 encryption policies.`,
	}
	noRecoveryFlag = &boolFlag{
		Name:  "no-recovery",
		Usage: `Don't ask to generate a recovery passphrase.`,
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
	userFlag = &stringFlag{
		Name:    "user",
		ArgName: "USERNAME",
		Usage: `Specify which user should be used for login passphrases
			or to which user's keyring keys should be provisioned.`,
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

func matchMetadataFlag(flagValue string) (mountpoint, descriptor string, err error) {
	matches := idFlagRegex.FindStringSubmatch(flagValue)
	if matches == nil {
		return "", "", fmt.Errorf("flag value %q does not have format %s",
			flagValue, mountpointIDArg)
	}
	log.Printf("parsed flag: mountpoint=%q descriptor=%s", matches[1], matches[2])
	return matches[1], matches[2], nil
}

// parseMetadataFlag takes the value of either protectorFlag or policyFlag
// formatted as MOUNTPOINT:DESCRIPTOR, and returns a context for the mountpoint
// and a string for the descriptor.
func parseMetadataFlag(flagValue string, targetUser *user.User) (*actions.Context, string, error) {
	mountpoint, descriptor, err := matchMetadataFlag(flagValue)
	if err != nil {
		return nil, "", err
	}
	ctx, err := actions.NewContextFromMountpoint(mountpoint, targetUser)
	return ctx, descriptor, err
}

// getProtectorFromFlag gets an existing locked protector from protectorFlag.
func getProtectorFromFlag(flagValue string, targetUser *user.User) (*actions.Protector, error) {
	ctx, descriptor, err := parseMetadataFlag(flagValue, targetUser)
	if err != nil {
		return nil, err
	}
	return actions.GetProtector(ctx, descriptor)
}

// getPolicyFromFlag gets an existing locked policy from policyFlag.
func getPolicyFromFlag(flagValue string, targetUser *user.User) (*actions.Policy, error) {
	ctx, descriptor, err := parseMetadataFlag(flagValue, targetUser)
	if err != nil {
		return nil, err
	}
	return actions.GetPolicy(ctx, descriptor)
}

// parseUserFlag returns the user specified by userFlag or the current effective
// user if the flag value is missing.
func parseUserFlag() (targetUser *user.User, err error) {
	if userFlag.Value != "" {
		return user.Lookup(userFlag.Value)
	}
	return util.EffectiveUser()
}

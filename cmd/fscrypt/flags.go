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
	"fmt"
	"log"
	"os/user"
	"regexp"
	"time"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/cmd"
	"github.com/google/fscrypt/security"
	"github.com/google/fscrypt/util"
)

// Bool flags: used to switch some behavior on or off
var (
	legacyFlag = &cmd.BoolFlag{
		Name: "legacy",
		Usage: `Allow for support of older kernels with ext4 (before
			v4.8) and F2FS (before v4.6) filesystems.`,
		Default: true,
	}
	skipUnlockFlag = &cmd.BoolFlag{
		Name: "skip-unlock",
		Usage: `Leave the directory in a locked state after setup.
			"fscrypt unlock" will need to be run in order to use the
			directory.`,
	}
	dropCachesFlag = &cmd.BoolFlag{
		Name: "drop-caches",
		Usage: `After purging the keys from the keyring, drop the
			associated caches for the purge to take effect. Without
			this flag, cached encrypted files may still have their
			plaintext visible. Requires root privileges.`,
		Default: true,
	}
)

// Option flags: used to specify options instead of being prompted for them
var (
	timeTargetFlag = &cmd.DurationFlag{
		Name:    "time",
		ArgName: "TIME",
		Usage: `Set the global options so that passphrase hashing takes
			TIME long. TIME should be formatted as a sequence of
			decimal numbers, each with optional fraction and a unit
			suffix, such as "300ms", "1.5s" or "2h45m". Valid time
			units are "ms", "s", "m", and "h".`,
		Default: 1 * time.Second,
	}
	sourceFlag = &cmd.StringFlag{
		Name:    "source",
		ArgName: "SOURCE",
		Usage: fmt.Sprintf(`New protectors will have type SOURCE. SOURCE
			can be one of pam_passphrase, custom_passphrase, or
			raw_key. If not specified, the user will be prompted for
			the source, with a default pulled from %s.`,
			actions.ConfigFileLocation),
	}
	nameFlag = &cmd.StringFlag{
		Name:    "name",
		ArgName: "PROTECTOR_NAME",
		Usage: `New custom_passphrase and raw_key protectors will be
			named PROTECTOR_NAME. If not specified, the user will be
			prompted for a name.`,
	}
	keyFileFlag = &cmd.StringFlag{
		Name:    "key",
		ArgName: "FILE",
		Usage: `Use the contents of FILE as the wrapping key when
			creating or unlocking raw_key protectors. FILE should be
			formatted as raw binary and should be exactly 32 bytes
			long.`,
	}
	userFlag = &cmd.StringFlag{
		Name:    "user",
		ArgName: "USERNAME",
		Usage: `Specifiy which user should be used for login passphrases
			or to which user's keyring keys should be provisioned.`,
	}
	protectorFlag = &cmd.StringFlag{
		Name:    "protector",
		ArgName: "MOUNTPOINT:ID",
		Usage: `Specify an existing protector on filesystem MOUNTPOINT
			with protector descriptor ID which should be used in the
			command.`,
	}
	unlockWithFlag = &cmd.StringFlag{
		Name:    "unlock-with",
		ArgName: "MOUNTPOINT:ID",
		Usage: `Specify an existing protector on filesystem MOUNTPOINT
			with protector descriptor ID which should be used to
			unlock a policy (usually specified with --policy). This
			flag is only useful if a policy is protected with
			multiple protectors. If not specified, the user will be
			prompted for a protector.`,
	}
	policyFlag = &cmd.StringFlag{
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
func parseMetadataFlag(flagValue string, target *user.User) (*actions.Context, string, error) {
	mountpoint, descriptor, err := matchMetadataFlag(flagValue)
	if err != nil {
		return nil, "", err
	}
	ctx, err := actions.NewContextFromMountpoint(mountpoint, target)
	return ctx, descriptor, err
}

// getProtectorFromFlag gets an existing locked protector from protectorFlag.
func getProtectorFromFlag(flagValue string, target *user.User) (*actions.Protector, error) {
	ctx, descriptor, err := parseMetadataFlag(flagValue, target)
	if err != nil {
		return nil, err
	}
	return actions.GetProtector(ctx, descriptor)
}

// getPolicyFromFlag gets an existing locked policy from policyFlag.
func getPolicyFromFlag(flagValue string, target *user.User) (*actions.Policy, error) {
	ctx, descriptor, err := parseMetadataFlag(flagValue, target)
	if err != nil {
		return nil, err
	}
	return actions.GetPolicy(ctx, descriptor)
}

// parseUserFlag returns the user specified by userFlag or the current effective
// user if the flag value is missing. If the effective user is root, however, a
// user must specified in the flag. If checkKeyring is true, we also make sure
// there are no problems accessing the user keyring.
func parseUserFlag(checkKeyring bool) (targetUser *user.User, err error) {
	if userFlag.Value != "" {
		targetUser, err = user.Lookup(userFlag.Value)
	} else {
		if util.IsUserRoot() {
			return nil, ErrSpecifyUser
		}
		targetUser, err = util.EffectiveUser()
	}
	if err != nil {
		return nil, err
	}

	if checkKeyring {
		_, err = security.UserKeyringID(targetUser, true)
	}
	return targetUser, err
}

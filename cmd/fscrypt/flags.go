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
		Name:    "legacy",
		Usage:   `Configure fscrypt to support older kernels.`,
		Default: true,
	}
	skipUnlockFlag = &cmd.BoolFlag{
		Name:  "skip-unlock",
		Usage: "Leave the directory in a locked state after setup.",
	}
	dropCachesFlag = &cmd.BoolFlag{
		Name: "drop-caches",
		Usage: `After purging the keys from the keyring, drop the
			associated caches for the purge to take effect.`,
		Default: true,
	}
)

// Option flags: used to specify options instead of being prompted for them
var (
	timeTargetFlag = &cmd.DurationFlag{
		Name:    "time",
		ArgName: "time",
		Usage: `Set the global options so that passphrase hashing takes
			<time> long.`,
		Default: 1 * time.Second,
	}
	sourceFlag = &cmd.StringFlag{
		Name:    "source",
		ArgName: "source",
		Usage: `New protectors will have type <source> (one of
			pam_passphrase, custom_passphrase, or raw_key).`,
	}
	nameFlag = &cmd.StringFlag{
		Name:    "name",
		ArgName: "name",
		Usage:   "Use <name> as the name for a new protector.",
	}
	keyFileFlag = &cmd.StringFlag{
		Name:    "key",
		ArgName: "path",
		Usage:   "Use the file at <path> as the protector key.",
	}
	userFlag = &cmd.StringFlag{
		Name:    "user",
		ArgName: "username",
		Usage: `Specify which user should be used for login passphrases
			or to which user's keyring keys should be provisioned.`,
	}
	mountpointIDArg = usedMountpointArg.ArgName + ":id"
	protectorFlag   = &cmd.StringFlag{
		Name:    "protector",
		ArgName: mountpointIDArg,
		Usage: fmt.Sprintf(`An existing protector on %s with hexadecimal
			id <id>.`, usedMountpointArg),
	}
	unlockWithFlag = &cmd.StringFlag{
		Name:    "unlock-with",
		ArgName: mountpointIDArg,
		Usage: fmt.Sprintf(`The protector that should be used to unlock
			the policy specified with %s.`, policyFlag),
	}
	policyFlag = &cmd.StringFlag{
		Name:    "policy",
		ArgName: mountpointIDArg,
		Usage: fmt.Sprintf(`An existing policy on %s with hexadecimal id
			<id>.`, usedMountpointArg),
	}
)

// The first group corresponds to the mountpoint string. The second group
// corresponds to the hexideciamal descriptor.
var idFlagRegex = regexp.MustCompile("^([[:print:]]+):([[:alnum:]]+)$")

func matchMetadataFlag(flagValue string) (mountpoint, descriptor string, err error) {
	matches := idFlagRegex.FindStringSubmatch(flagValue)
	if matches == nil {
		return "", "", fmt.Errorf("flag value %q does not have format %q",
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
		if targetUser, err = user.Lookup(userFlag.Value); err != nil {
			return nil, err
		}
	} else {
		targetID := util.CurrentUserID()
		if targetID == 0 {
			return nil, ErrSpecifyUser
		}
		targetUser = util.GetUser(targetID)
	}

	if checkKeyring {
		if _, err = security.UserKeyringID(targetUser, true); err != nil {
			return nil, err
		}
	}
	return targetUser, nil
}

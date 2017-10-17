/*
 * ext4.go - Handles command line processing for fscrypt-ext4.
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

	"github.com/google/fscrypt/cmd"
)

var (
	mountpointArg = &cmd.Argument{
		ArgName: "mountpoint",
		Usage:   "the mountpoint of an ext4 filesystem",
	}
	deviceArg = &cmd.Argument{
		ArgName: "device",
		Usage:   "the path to a device containing an ext4 filesystem",
	}
	ext4Usage = fmt.Sprintf("(%s | %s) [options]", mountpointArg, deviceArg)
)

func main() { ext4Command.Run(nil) }

var ext4Command = &cmd.Command{
	Title: "manage ext4 encryption feature flag",
	UsageLines: []string{
		fmt.Sprintf("enable  %s", ext4Usage),
		fmt.Sprintf("disable %s", ext4Usage),
		cmd.VersionUsage,
	},
	SubCommands: []*cmd.Command{enableCommand, disableCommand, cmd.VersionCommand},
	Arguments:   []*cmd.Argument{mountpointArg, deviceArg},
	Flags:       []cmd.Flag{cmd.ForceFlag, cmd.VerboseFlag, cmd.HelpFlag},
	ManPage:     &cmd.ManPage{Name: "fscrypt-ext4", Section: 8},
}
var enableCommand = &cmd.Command{
	Name:             "enable",
	Title:            "turn on encryption for an ext4 filesystem",
	UsageLines:       []string{ext4Usage},
	InheritArguments: true,
	InheritFlags:     true,
	Action:           func(c *cmd.Context) error { return toggleState(c, true) },
}
var disableCommand = &cmd.Command{
	Name:             "disable",
	Title:            "turn off encryption for an ext4 filesystem",
	UsageLines:       []string{ext4Usage},
	InheritArguments: true,
	InheritFlags:     true,
	Action:           func(c *cmd.Context) error { return toggleState(c, false) },
}

func toggleState(c *cmd.Context, enable bool) error {
	fmt.Fprintf(cmd.Output, "Toggle value = %v", enable)
	return nil
}

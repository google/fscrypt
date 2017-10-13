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

// Arguments used with the ext4 enable/disable commands.
var (
	MountpointArg = &cmd.Argument{
		ArgName: "mountpoint",
		Usage:   "the path to an ext4 filesystem's mountpoint",
	}
	DeviceArg = &cmd.Argument{
		ArgName: "device",
		Usage:   "the path to a device containing an ext4 filesystem",
	}
	Ext4Usage = fmt.Sprintf("(%s | %s) [options]", MountpointArg, DeviceArg)
)

// Commands for running the ext4 enable/disable commands.
var ()

var Ext4Command = &cmd.Command{
	Title: "toggle ext4 filesystem encryption flag",
	UsageLines: []string{
		fmt.Sprintf("(enable | disable) %s", Ext4Usage),
		cmd.VersionUsage,
	},
	SubCommands: []*cmd.Command{EnableCommand, DisableCommand, cmd.VersionCommand},
	Arguments:   []*cmd.Argument{MountpointArg, DeviceArg},
	Flags:       []cmd.Flag{cmd.ForceFlag, cmd.VerboseFlag, cmd.HelpFlag},
	ManPage: &cmd.ManPage{
		Title:   "fscrypt-ext4",
		Section: 8,
	},
}

var EnableCommand = &cmd.Command{
	Name:             "enable",
	Title:            "turn on encryption for an ext4 filesystem",
	UsageLines:       []string{Ext4Usage},
	InheritArguments: true,
	InheritFlags:     true,
	Action:           func(ctx *cmd.Context) error { return toggleState(ctx, true) },
}

var DisableCommand = &cmd.Command{
	Name:             "disable",
	Title:            "turn off encryption for an ext4 filesystem",
	UsageLines:       []string{Ext4Usage},
	InheritArguments: true,
	InheritFlags:     true,
	Action:           func(ctx *cmd.Context) error { return toggleState(ctx, false) },
}

func main() { Ext4Command.Run() }

func toggleState(ctx *cmd.Context, enable bool) error {
	fmt.Fprintf(cmd.Output, "Toggle value = %v", enable)
	return nil
}

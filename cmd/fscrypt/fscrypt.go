/*
 * fscrypt.go - File which starts up and runs the application. Initializes
 * information about the application like the name, version, author, etc...
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

/*
fscrypt is a command line tool for managing linux filesystem encryption.
*/

package main

import (
	"fmt"

	"github.com/google/fscrypt/cmd"
)

func main() { fscryptCommand.Run() }

var fscryptCommand = cmd.Command{
	Title: "manage linux filesystem encryption",
	UsageLines: []string{
		fmt.Sprintf("<command> [arguments] [command options] [%s | %s]",
			cmd.VerboseFlag, cmd.QuietFlag),
		cmd.VersionUsage,
	},
	SubCommands: []*Command{
		&setupCommand,
		&encryptCommand,
		// unlockCommand,
		// purgeCommand,
		// statusCommand,
		// metadataCommand,
		cmd.VersionCommand,
	},
	Flags:   []cmd.Flag{cmd.VerboseFlag, cmd.QuietFlag, cmd.HelpFlag},
	ManPage: &cmd.ManPage{Name: "fscrypt", Section: 8},
}

// setup performs global or per-filesystem initialization of fscrypt data.
var setupCommand = &cmd.Command{
	Name:  "setup",
	Title: "setup a system/filesystem to use fscrypt",
	UsageLines: []string{
		fmt.Sprintf("[options]"),
		fmt.Sprintf("%s [%s]", mountpointArg, cmd.ForceFlag),
	},
	Arguments:    []*cmd.Argument{mountpointArg},
	InheritFlags: true,
	Flags:        []cmd.Flag{configFileFlag, targetFlag, legacyFlag, cmd.ForceFlag},
	ManPage:      &cmd.ManPage{Name: "fscrypt-setup", Section: 8},
	Action:       setupAction,
}

func setupAction(c *cmd.Context) error {
	switch len(c.Args) {
	case 0:
		// Case (1) - global setup
		return createGlobalConfig(configFileFlag.Value)
	case 1:
		// Case (2) - filesystem setup
		return setupFilesystem(c.Args[0])
	default:
		return cmd.CheckExpectedArgs(c, 1, true)
	}
}

// encrypt performs the functions of setupDirectory and Unlock in one command.
var encryptCommand = &cmd.Command{}

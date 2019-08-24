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
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/urfave/cli"
)

var (
	// Current version of the program (set by Makefile)
	version string
	// Formatted build time (set by Makefile)
	buildTime string
	// Authors to display in the info command
	Authors = []cli.Author{{
		Name:  "Joe Richey",
		Email: "joerichey@google.com",
	}}
)

func main() {
	cli.AppHelpTemplate = appHelpTemplate
	cli.CommandHelpTemplate = commandHelpTemplate
	cli.SubcommandHelpTemplate = subcommandHelpTemplate

	// Create our command line application
	app := cli.NewApp()
	app.Usage = shortUsage
	app.Authors = Authors
	app.Copyright = apache2GoogleCopyright

	// Grab the version and compilation time passed in from the Makefile.
	app.Version = version
	app.Compiled, _ = time.Parse(time.UnixDate, buildTime)
	app.OnUsageError = onUsageError

	// Setup global flags
	cli.HelpFlag = helpFlag
	cli.VersionFlag = versionFlag
	cli.VersionPrinter = func(c *cli.Context) {
		cli.HelpPrinter(c.App.Writer, versionInfoTemplate, c.App)
	}
	app.Flags = universalFlags

	// We hide the help subcommand so that "fscrypt <command> --help" works
	// and "fscrypt <command> help" does not.
	app.HideHelp = true

	// Initialize command list and setup all of the commands.
	app.Action = defaultAction
	app.Commands = []cli.Command{Setup, Encrypt, Unlock, Purge, Status, Metadata}
	for i := range app.Commands {
		setupCommand(&app.Commands[i])
	}

	app.Run(os.Args)
}

// setupCommand performs some common setup for each command. This includes
// hiding the help, formatting the description, adding in the necessary
// flags, setting up error handlers, etc... Note that the command is modified
// in place and its subcommands are also setup.
func setupCommand(command *cli.Command) {
	command.Description = wrapText(command.Description, indentLength)
	command.HideHelp = true
	command.Flags = append(command.Flags, universalFlags...)

	if command.Action == nil {
		command.Action = defaultAction
	}

	// Setup function handlers
	command.OnUsageError = onUsageError
	if len(command.Subcommands) == 0 {
		command.Before = setupBefore
	} else {
		// Setup subcommands (if applicable)
		for i := range command.Subcommands {
			setupCommand(&command.Subcommands[i])
		}
	}
}

// setupBefore makes sure our logs, errors, and output are going to the correct
// io.Writers and that we haven't over-specified our flags. We only print the
// logs when using verbose, and only print normal stuff when not using quiet.
func setupBefore(c *cli.Context) error {
	log.SetOutput(ioutil.Discard)
	c.App.Writer = ioutil.Discard

	if verboseFlag.Value {
		log.SetOutput(os.Stdout)
	}
	if !quietFlag.Value {
		c.App.Writer = os.Stdout
	}
	return nil
}

// defaultAction will be run when no command is specified.
func defaultAction(c *cli.Context) error {
	// Always default to showing the help
	if helpFlag.Value {
		cli.ShowAppHelp(c)
		return nil
	}

	// Only exit when not calling with the help command
	var message string
	if args := c.Args(); args.Present() {
		message = fmt.Sprintf("command \"%s\" not found", args.First())
	} else {
		message = "no command was specified"
	}
	return &usageError{c, message}
}

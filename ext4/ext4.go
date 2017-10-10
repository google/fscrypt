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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/urfave/cli"
)

var (
	// Setup command parsing
	cmdName = os.Args[0]
	set     = flag.NewFlagSet(cmdName, flag.ContinueOnError)
	// Flags for our command
	forceFlag   = set.Bool("force", false, "Suppress all warnings and do not prompt")
	versionFlag = set.Bool("version", false, "Print the fscrypt version.")
	helpFlag    = set.Bool("help", false, "Print this help text.")
	// fscrypt's version (set by Makefile)
	version string
)

const (
	manPage  = "fscrypt-ext4(8)"
	manBrief = "enable or disable encryption on an ext4 filesystem"
	usageFmt = `
Usage:
	%[1]s [enable | disable] <mountpoint> [--force]
	%[1]s --help
	%[1]s --version

Arguments:
  	<mountpoint> - path to an ext4 filesystem
`
)

func printAndExit(err error, printUsage bool) {
	var w io.Writer
	var rc int
	if err == nil {
		w = os.Stdout
		rc = 0
		fmt.Fprintf(w, "%s - %s\n", cmdName, manBrief)
	} else {
		w = os.Stderr
		rc = 1
		fmt.Fprintf(w, "%s: %v\n", cmdName, err)
	}
	if printUsage {
		fmt.Fprintf(w, usageFmt, cmdName)
		fmt.Fprintln(w, "\nOptions:")
		set.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(w, "\t--%s\n\t\t%s\n", f.Name, f.Usage)
		})
		fmt.Fprintf(w, "\nSee the %s man page for more info.\n", manPage)
	}
	os.Exit(rc)
}

func main() {
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

	set.SetOutput(ioutil.Discard)
	if err := set.Parse(os.Args[1:]); err != nil {
		printAndExit(err, true)
	}
	if *helpFlag {
		printAndExit(nil, true)
	}
	if *versionFlag {
		fmt.Println(version)
		return
	}
	if set.NArg() != 2 {
		printAndExit(fmt.Errorf("expected 2 arguments (got %d)", set.NArg()), true)
	}

	_, err := NewExt4Filesystem(set.Arg(1))
	if err != nil {
		printAndExit(err, false)
	}

	switch command := set.Arg(0); command {
	case "enable":
		fmt.Println("Enabling encryption not implemented")
	case "disable":
		fmt.Println("Disabling encryption not implemented")
	default:
		printAndExit(fmt.Errorf("invalid command %q", command), true)
	}
}

/*
 * cmd.go - Main interface to cmd package (running, Cmd and Flag structs, etc)
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

// Package cmd is the common library for writing command line binaries.
// This package is mainly a wrapper around github.com/urfave/cli, but provides
// additional support to make the usage look similar to the man page.
//
// The main componets are the `Cmd`, `Argument`, and `Flag` types which can be
// used to define a top-level command with many potential subcommands. This
// package also presents a smaller interface than urfave/cli, making it easier
// to use for other commands.
package cmd

import "os"

// Command represents a command with many potential top-level commands. This is
// transformed into a cli.Command in Run().
type Command struct {
	Name       string
	UsageLines []string
	SubCmds    []*Command
	Arguments  []*Argument
	Flags      []Flag
	ManPage    *ManEntry
	Action     CommandFunc
}

// Argument represents a parameter passed to a function. It has an optional
// usage explains how it should be used.
type Argument struct {
	ArgName string
	Usage   string
}

// ManEntry represents an entry in a man page with a name, section, and title.
type ManEntry struct {
	Name    string
	Section int
	Title   string
}

// CommandFunc contains the implementation of a command. The provided args have
// the flags and leading command names removed. If a normal error is returned,
// it is printed out (with an optional explanation) and exits with FailureCode.
// If a usage error is returned, it is printed out with the command's usage and
// exits with UsageFailureCode. Returning nil causes an exit with success.
type CommandFunc func(args []string) error

// Run executes the command with os.Args, equivalent to c.RunArgs(os.Args).
func (c *Command) Run() {
	c.RunArgs(os.Args)
}

// RunArgs executes the command with the provided args. If the Name argument is
// empty, args[0]'s basename is used instead. If the command fails, this method
// will not return.
func (c *Command) RunArgs(args []string) {
	// TODO(joerichey): Implement conversion to cli.Command
}

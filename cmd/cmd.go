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

import (
	"fmt"
	"io"
	"os"
	"text/template"
	"time"

	"github.com/blang/semver"
)

// Context represents the state of a running application, and is the only thing
// passed to a CommandFunc.
type Context struct {
	Command  *Command
	Parent   *Context
	Info     *Info
	Args     []string
	flagArgs []string
}

// FullName returns the space-separated name of the command and all parents.
func (ctx *Context) FullName() string {
	if ctx.Parent == nil {
		return ctx.Command.Name
	}
	return fmt.Sprintf("%s %s", ctx.Parent.FullName(), ctx.Command.Name)
}

// ManPage returns the man page entry for this context. It is either the ManPage
// for the the current command or the closet Parent.
func (ctx *Context) ManPage() *ManPage {
	if ctx.Command.ManPage.Section != 0 || ctx.Parent == nil {
		return ctx.Command.ManPage
	}
	return ctx.Parent.ManPage()
}

// Creates an anonymous template from the text, and runs it with the provided
// Context and writer. Panics if text has a bad format or execution fails.
func (ctx *Context) executeTemplate(w io.Writer, text string) {
	tmpl := template.Must(template.New("").Parse(text))
	if err := tmpl.Execute(w, ctx); err != nil {
		panic(err)
	}
}

func (ctx *Context) execute() {
	fmt.Printf("%+v\n", ctx)
	return
}

// Info is a parsed view of the corresponding global variables.
type Info struct {
	Version   semver.Version
	BuildTime time.Time
	Authors   []Author
	Copyright string
}

// Author contains the contact information for a contributor.
type Author struct {
	Name  string
	Email string
}

// Argument represents a parameter passed to a function. It has an optional
// usage explains how it should be used.
type Argument struct {
	ArgName string
	Usage   string
}

func (a *Argument) String() string { return fmt.Sprintf("<%s>", a.ArgName) }

// ManPage a man page with a title and section.
type ManPage struct {
	Title   string
	Section int
}

// CommandFunc contains the implementation of a command. If a normal error is
// returned, the error will be printed out (with an optional explanation) and
// Run will exit with FailureCode. If a usage error is returned, the error and
// the commnd's usage are printed out and Run will exit with UsageFailureCode.
// Returning nil causes Run to return.
type CommandFunc func(ctx *Context) error

// Command represents a command with many potential top-level commands. This is
// transformed into a cli.Command in Run().
type Command struct {
	Name             string
	Title            string
	UsageLines       []string
	SubCommands      []*Command
	InheritArguments bool
	Arguments        []*Argument
	InheritFlags     bool
	Flags            []Flag
	ManPage          *ManPage
	Action           CommandFunc
}

// Run executes the command with os.Args, equivalent to c.RunArgs(os.Args).
func (c *Command) Run() {
	c.RunArgs(os.Args)
}

// RunArgs executes the command with the provided args. If the Name argument is
// empty, args[0]'s basename is used instead. If the command fails, this method
// will not return.
func (c *Command) RunArgs(args []string) {
	binaryName, args := args[0], args[1:]
	if c.Name == "" {
		c.Name = binaryName
	}

	// Create our initial context by sorting the args and parsing the tags.
	ctx := &Context{
		Command: c,
		Info:    parseInfo(),
	}
	ctx.Args, ctx.flagArgs = sortArgs(args)

	ctx.execute()
}

// Divide the arguments into flag arguments (those starting with "-") and normal
// arguments. If "--" appears in the list, it will classified as a normal
// argument as well as all arguments following it. Also removes empty args.
func sortArgs(args []string) (normalArgs, flagArgs []string) {
	var arg string
	for len(args) > 0 {
		arg, args = args[0], args[1:]
		if arg == "" {
			continue
		}
		if arg == "--" {
			normalArgs = append(normalArgs, arg)
			normalArgs = append(normalArgs, args...)
			return
		} else if arg[0] == '-' {
			flagArgs = append(flagArgs, arg)
		} else {
			normalArgs = append(normalArgs, arg)
		}
	}
	return
}

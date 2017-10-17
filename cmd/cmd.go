/*
 * cmd.go - Main interface to cmd package (Context, Command, Flag, etc...)
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

// Package cmd is the common library for writing command line binaries. The main
// componets are the `Command`, `Context`, `Argument`, and `Flag` types which
// can be used to define a top-level command with many potential subcommands.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// Command represents a command with many potential sub-commands.
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
	Action           Action
}

// Run executes the command with os.Args as the provided args, equivalent to
// c.RunArgs(os.Args, helpTextMap).
func (c *Command) Run(helpTextMap map[error]string) {
	c.RunArgs(os.Args, helpTextMap)
}

// RunArgs executes the command with the provided args. If the Name argument is
// empty, args[0]'s basename is used instead. The helpTextMap provides a
// translation from error causes to explanation strings. If the command fails,
// this method will not return.
func (c *Command) RunArgs(args []string, helpTextMap map[error]string) {
	binaryPath, args := args[0], args[1:]
	if c.Name == "" {
		c.Name = filepath.Base(binaryPath)
	}

	// Create our initial context by sorting the arguments.
	ctx := &Context{Command: c, helpTextMap: helpTextMap}
	ctx.Args, ctx.flagArgs = sortArgs(args)

	ctx.run()
}

// Action contains the implementation of a command. If a normal error is
// returned, the error will be printed out (with an optional explanation) and
// Run will exit with FailureCode. If a usage error is returned, the error and
// the commnd's usage are printed out and Run will exit with UsageFailureCode.
// Returning nil causes Run to return.
type Action func(ctx *Context) error

// Context represents the state of a running application, and is the only thing
// passed to an Action.
type Context struct {
	// The current command being executed
	Command *Command
	// The context of the parent command before this command was executed.
	// Nil if this is the root context.
	Parent *Context
	// The non-flag arguments being passed to the command.
	Args []string
	// The flag arguments being passed to the command.
	flagArgs []string
	// The mapping of error causes to help strings
	helpTextMap map[error]string
}

// FullArguments returns the list of arguments for the current command and its
// parent arguments (if InheritArguments) is true.
func (ctx *Context) FullArguments() []*Argument {
	if ctx.Parent == nil || !ctx.Command.InheritArguments {
		return ctx.Command.Arguments
	}
	return append(ctx.Command.Arguments, ctx.Parent.FullArguments()...)
}

// FullFlags returns the list of flags for the current command and its parent
// arguments (if InheritFlags) is true.
func (ctx *Context) FullFlags() []Flag {
	if ctx.Parent == nil || !ctx.Command.InheritFlags {
		return ctx.Command.Flags
	}
	return append(ctx.Command.Flags, ctx.Parent.FullFlags()...)
}

// FullName returns the space-separated name of the command and all parents.
func (ctx *Context) FullName() string {
	if ctx.Parent == nil {
		return ctx.Command.Name
	}
	return fmt.Sprintf("%s %s", ctx.Parent.FullName(), ctx.Command.Name)
}

// Info returns the same information as cmd.Info. This method only exists so
// that Info can be accessed in an output template.
func (*Context) Info() *InfoData {
	return Info
}

// ManPage returns the man page entry for this context. It is either the ManPage
// for the the current command or the closet Parent.
func (ctx *Context) ManPage() *ManPage {
	if ctx.Parent == nil || ctx.Command.ManPage != nil {
		return ctx.Command.ManPage
	}
	return ctx.Parent.ManPage()
}

// getHelpText first tries to find a helpTextMap in either this context, or a
// parent context. Then, it looks up an error by it's cause, returning the
// appropriate help text. If no help text can be found, return an empty string.
func (ctx *Context) getHelpText(err error) string {
	if ctx.helpTextMap != nil {
		return ctx.helpTextMap[errors.Cause(err)]
	}
	if ctx.Parent == nil {
		return ""
	}
	return ctx.Parent.getHelpText(err)
}

// Argument represents a parameter passed to a function. It has an optional
// usage explains how it should be used.
type Argument struct {
	ArgName string
	Usage   string
}

func (a *Argument) String() string { return fmt.Sprintf("<%s>", a.ArgName) }

// ManPage a man page with a name and section.
type ManPage struct {
	Name    string
	Section int
}

func (m *ManPage) String() string { return fmt.Sprintf("%s(%d)", m.Name, m.Section) }

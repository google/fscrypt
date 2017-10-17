/*
 * run.go - Functions to setup and run Command Actions.
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

package cmd

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

var (
	// HelpAction is performed whenever a Command uses the HelpFlag.
	HelpAction Action = func(ctx *Context) error {
		ExecuteTemplate(os.Stdout, TemplateTitle, ctx)
		ExecuteTemplate(os.Stdout, TemplateUsage, ctx)
		return nil
	}
	// DefaultAction is preformed when a Command has no Action specified.
	DefaultAction = HelpAction
	// stopFlag indicates that everything after the flag is an argument, not
	// a command or flag.
	stopFlag = "--"
)

// TemplateTitle describes the format of a Command's one line title.
var TemplateTitle = "{{.FullName}}{{if .Command.Title}} - {{.Command.Title}}{{end}}\n"

// TemplateUsage describes the format of a Command's usage.
var TemplateUsage = `{{with $lines := .Command.UsageLines}}
Usage:
{{- range $lines}}
	{{$.FullName}} {{. -}}
{{end}}
{{end -}}

{{with $commands := .Command.SubCommands}}
Commands:
{{- range $commands}}
	{{.Name}}{{if .Title}}	- {{.Title}}{{end -}}
{{end}}
{{end -}}

{{with $arguments := .FullArguments}}
Arguments:
{{- range $arguments}}
	{{.}}
		{{WrapText .Usage 2 -}}
{{end}}
{{end -}}

{{with $flags := .FullFlags}}
Options:
{{- range $flags}}
	{{.}}
		{{WrapText .FullUsage 2 -}}
{{end}}
{{end -}}

{{with .ManPage}}
For more information, see {{.}}.
{{end -}}
`

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
		if arg == stopFlag {
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

// Returns the name of the requested sub-command or empty string (if a
// sub-command was not requested).
func subCommandName(ctx *Context) string {
	// We must have actual arguments and subcommands to run a sub-command.
	if len(ctx.Command.SubCommands) == 0 || len(ctx.Args) == 0 {
		return ""
	}
	name := ctx.Args[0]
	if name == stopFlag {
		return ""
	}
	return name
}

// Returns the appropriate child context with a sub-command whose name matches
// the provided name. If no sub-commands match the provied name, handle the
// appropriate error and do not return.
func getSubContext(ctx *Context, name string) *Context {
	for _, subCommand := range ctx.Command.SubCommands {
		if subCommand.Name == name {
			return &Context{
				Command:  subCommand,
				Parent:   ctx,
				Args:     ctx.Args[1:],
				flagArgs: ctx.flagArgs,
			}
		}
	}
	ctx.processError(UsageError(fmt.Sprintf("unknown command %q", name)))
	return nil
}

// Configures the Output and log output io.Writers. Called before running
// commands but after processing flags.
func setupOutput() {
	if VerboseFlag.Value {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(ioutil.Discard)
	}
	if Output != nil {
		return
	}
	if QuietFlag.Value {
		Output = ioutil.Discard
	} else {
		Output = os.Stdout
	}
}

// Remove the stopFlag from the args if it is present. Args are modified
// in-place and the correctly sized slice is returned.
func setupArgs(args []string) []string {
	for i, arg := range args {
		if arg == stopFlag {
			return append(args[:i], args[i+1:]...)
		}
	}
	return args
}

// Return a command's action, the HelpAction, or DefaultAction.
func getAction(cmd *Command) Action {
	if HelpFlag.Value {
		return HelpAction
	}
	if cmd.Action == nil {
		return DefaultAction
	}
	return cmd.Action
}

func (ctx *Context) run() {
	if name := subCommandName(ctx); name != "" {
		getSubContext(ctx, name).run()
		return
	}

	flagSet := flag.NewFlagSet("", flag.ContinueOnError)
	flagSet.SetOutput(ioutil.Discard)
	for _, flag := range ctx.FullFlags() {
		flag.Apply(flagSet)
	}
	if err := flagSet.Parse(ctx.flagArgs); err != nil {
		ctx.processError(err)
		return
	}

	setupOutput()
	ctx.Args = setupArgs(ctx.Args)
	action := getAction(ctx.Command)

	ctx.processError(action(ctx))
}

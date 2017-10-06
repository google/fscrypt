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

// Package cmd is the common library for writing fscrypt command line binaries.
// This package is mainly a wrapper around github.com/urfave/cli, but provides
// additional support to make the usage look similar to the man page.
//
// The main componets are the `Cmd` and `Flag` types which can be used to define
// a top-level command with many potential subcommands. This package also
// presents a smaller interface than urfave/cli, making it easier to use for
// other commands.
package cmd

// Command represents a command with many potential top-level commands. This is
// trand
type Cmd struct {
	Name string
	UsageLines []string
	SubCmds []Cmd
	Arguments []Argument
	Flags []cli.Flag
	Man *ManEntry
	Action CommandFunc
}

type Argument struct {
	Name string
	Usage string
}

type ManEntry struct {
	Title string
	Section int
}

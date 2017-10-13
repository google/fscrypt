/*
 * version.go - Version subcommand that can be added to any binary
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
	"fmt"

	"github.com/blang/semver"
)

// Templates for use with the version command, which both parse the Info var.
var (
	VersionTemplate     = "{{.FullName}} {{.Info.Version}}\n"
	VersionLongTemplate = `{{if .Info.BuildTime}}
Compiled:
	{{.Info.BuildTime}}
{{end}}

{{with $length := len .Info.Authors}}
{{if $length}}
Author{{if ne 1 $length}}s{{end}}:
{{range .Info.Authors}}
	{{.Name}}{{if .Email}} <{{.Email}}>{{end}}
{{end}}
{{end}}
{{end}}

{{if .Info.Copyright}}
Copyright:
{{.Info.Copyright}}
{{end}}`
)

// VersionCommand is a command which will display either the VersionTag (by
// default) or the full version information: version, copyright, authors, etc...
var VersionCommand = &Command{
	Name:       "version",
	Title:      "display this program's version information",
	UsageLines: []string{fmt.Sprintf("[%v]", longFlag)},
	Flags:      []Flag{longFlag, HelpFlag},
	Action:     versionAction,
}

// VersionUsage is a UsageLine to add to a Command with a version Subcommand.
var VersionUsage = VersionCommand.Name + " " + VersionCommand.UsageLines[0]

// longFlag tells the version command to display the longer version info.
var longFlag = &BoolFlag{
	Name:  "long",
	Usage: "Print the detailed version, build, and copyright information.",
}

func versionAction(ctx *Context) error {
	if ctx.Info.Version.Equals(semver.Version{}) {
		return ErrUnknownVersion
	}
	ctx.executeTemplate(Output, VersionTemplate)
	if longFlag.Value {
		ctx.executeTemplate(Output, VersionLongTemplate)
	}
	return nil
}

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
	"time"

	"github.com/blang/semver"
	"github.com/pkg/errors"
)

// Info contains global information about the program.
var Info = &InfoData{}

// InfoData describes the structure of our global program information
type InfoData struct {
	// Version (if set) will be displayed in both the short and long version
	// output. This can be set directly or using VersionTag at link time.
	Version semver.Version
	// BuildTime (if set) will be displayed in the long version output. This
	// can be set directory or by setting cmd.BuildTimeTag in a linking
	// flag. s
	//
	BuildTime time.Time
	// Authors (if non-empty) are displayed in the long version output.
	Authors []Author
	// Copyright (if set) is displayed in the long version output.
	Copyright string
}

// Author contains the contact information for a contributor.
type Author struct {
	Name  string
	Email string
}

// We have to use separate Tag variables, because build tags of the form:
//	"-X cmd.Info.Version=foo"
// are invalid.
var (
	// VersionTag can be set via the linker, and its value will be used to
	// set Info.Version. Format this tag using Semver (http://semver.org/).
	// Example:
	//	"-X cmd.VersionTag=1.2.3-beta"
	VersionTag string
	// BuildTimeTag can be set via the linker, and its value will be used to
	// set Info.BuildTime. Format this tag like the output of UNIX's `date`.
	// Example:
	//	"-X cmd.BuildTimeTag=Thu Oct 12 21:32:02 PDT 2017"
	BuildTimeTag string
)

func init() {
	var err error
	// parse the tag variables
	if VersionTag != "" {
		Info.Version, err = semver.ParseTolerant(VersionTag)
		if err != nil {
			panic(errors.Wrapf(err, "semver: parsing %q", VersionTag))
		}
	}
	if BuildTimeTag != "" {
		Info.BuildTime, err = time.Parse(time.UnixDate, BuildTimeTag)
		if err != nil {
			panic(err)
		}
	}

	// fscrypt specific initialization
	Info.Authors = []Author{{
		Name:  "Joe Richey",
		Email: "joerichey@google.com",
	}}
	Info.Copyright = `Copyright 2017 Google, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.`
}

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

// TemplateVersionShort describes the format of the one line version command.
var TemplateVersionShort = "{{.FullName}} {{.Info.Version}}\n"

// TemplateVersionLong describes the format of the additional version data.
var TemplateVersionLong = `{{if not .Info.BuildTime.IsZero}}
Compiled:
	{{.Info.BuildTime}}
{{end -}}

{{with $length := len .Info.Authors}}
Author{{if ne 1 $length}}s{{end}}:
{{- range $.Info.Authors}}
	{{.Name}}{{if .Email}} <{{.Email}}>{{end -}}
{{end}}
{{end -}}

{{if .Info.Copyright}}
Copyright:
	{{.Info.Copyright}}
{{end}}`

func versionAction(ctx *Context) error {
	if Info.Version.Equals(semver.Version{}) {
		return ErrUnknownVersion
	}
	ExecuteTemplate(Output, TemplateVersionShort, ctx)
	if longFlag.Value {
		ExecuteTemplate(Output, TemplateVersionLong, ctx)
	}
	return nil
}

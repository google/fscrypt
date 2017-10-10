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

// Templates for use with the version command, which both parse the Info var.
var (
	VersionShortTemplate = "{{.Command}} version {{.VersionTag}}\n"
	VersionLongTemplate  = VersionShortTemplate + `{{if .Compiled}}
Compiled:
	{{.Compiled}}
{{end}}{{if len .Authors}}
Author{{with $length := len .Authors}}{{if ne 1 $length}}s{{end}}{{end}}:{{range .Authors}}
	{{.}}{{end}}
{{end}}{{if .Copyright}}
Copyright:
	{{.Copyright}}
{{end}}`
)

// Version is a command which will display either the VersionTag (by default) or
// the full version information (version, copyright, authors).
var Version = &Command{
	Name:       "version",
	UsageLines: []string{""},
	Flags:      []Flag{longFlag},
	Action:     versionAction,
}

// Using longFlag with the version command displays the longer version info.
var longFlag = &BoolFlag{
	Name:  "long",
	Usage: "Print the detailed version and copyright information.",
}

func versionAction(_ []string) error {
	if Info.VersionTag == "" {
		return ErrUnknownVersion
	}
	if longFlag.Value {

	} else {

	}
	return nil
}

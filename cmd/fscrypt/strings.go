/*
 * strings.go - File which contains the specific strings used for output and
 * formatting in fscrypt.
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
	"fmt"
	"strings"
)

// Global application strings
const (
	shortUsage = "A tool for managing Linux filesystem encryption"

	apache2GoogleCopyright = `Copyright 2017 Google, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.`
)

// Argument usage strings
const (
	directoryArg    = "DIRECTORY"
	mountpointArg   = "MOUNTPOINT"
	pathArg         = "PATH"
	mountpointIDArg = mountpointArg + ":ID"
)

// Text Templates which format our command line output (using text/template)
var (
	// indent is the prefix for the output lines in each section
	indent = strings.Repeat(" ", indentLength)
	// Top level help output: what is printed for "fscrypt" or "fscrypt --help"
	appHelpTemplate = `{{.HelpName}} - {{.Usage}}

Usage:
` + indent + `{{.HelpName}} COMMAND [arguments] [options]

Commands:{{range .VisibleCommands}}
` + indent + `{{join .Names ", "}}{{"\t- "}}{{.Usage}}{{end}}
{{if .Description}}
Description:
` + indent + `{{.Description}}
{{end}}
Options:
{{range .VisibleFlags}}{{.}}

{{end}}`

	// Command help output, used when a command has no subcommands
	commandHelpTemplate = `{{.HelpName}} - {{.Usage}}

Usage:
` + indent + `{{.HelpName}}{{if .ArgsUsage}} {{.ArgsUsage}}{{end}}{{if .VisibleFlags}} [options]{{end}}
{{if .Description}}
Description:
` + indent + `{{.Description}}
{{end}}{{if .VisibleFlags}}
Options:
{{range .VisibleFlags}}{{.}}

{{end}}{{end}}`

	// Subcommand help output, used when a command has subcommands
	subcommandHelpTemplate = `{{.HelpName}} - {{.Usage}}

Usage:
` + indent + `{{.HelpName}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}SUBCOMMAND [arguments]{{end}}{{if .VisibleFlags}} [options]{{end}}

Subcommands:{{range .VisibleCommands}}
` + indent + `{{join .Names ", "}}{{"\t- "}}{{.Usage}}{{end}}
{{if .Description}}
Description:
` + indent + `{{.Description}}
{{end}}{{if .VisibleFlags}}
Options:
{{range .VisibleFlags}}{{.}}

{{end}}{{end}}`

	// Additional info, used with "fscrypt version"
	versionInfoTemplate = `{{.HelpName}} - {{.Usage}}

{{if .Version}}Version:
` + indent + `{{.Version}}

{{end}}{{if not .Compiled.IsZero}}Compiled:
` + indent + `{{.Compiled}}

{{end}}{{if len .Authors}}Author{{with $length := len .Authors}}{{if ne 1 $length}}s{{end}}{{end}}:{{range .Authors}}
` + indent + `{{.}}{{end}}

{{end}}{{if .Copyright}}Copyright:
` + indent + `{{.Copyright}}

{{end}}`
)

// Add words to this map to have pluralize support them.
var plurals = map[string]string{
	"argument":   "arguments",
	"filesystem": "filesystems",
	"protector":  "protectors",
	"policy":     "policies",
}

// pluralize prints our the correct pluralization of a work along with the
// specified count. This means pluralize(1, "policy") = "1 policy" but
// pluralize(2, "policy") = "2 policies"
func pluralize(count int, word string) string {
	if count != 1 {
		word = plurals[word]
	}
	return fmt.Sprintf("%d %s", count, word)
}

/*
 * info.go - Global information about the program.
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
	"time"

	"github.com/urfave/cli"
)

// Info contains the global info for the functions.
var Info struct {
	// Program is the name of the top-level program being executed. If not
	// set it is set in cmd.RunArgs().
	Program string
	// VersionTag (if set) will be displayed in both the short and long
	// version output. VersionTag is not parsed, so any string will work.
	VersionTag string
	// BuildTime (if set) will be displayed in the long version output.
	BuildTime time.Time
	// Authors (if non-empty) are displayed in the long version output.
	Authors []cli.Author
	// Copyright (if set) is displayed in the long version output.
	Copyright string
}

// Linker flags of the form "-X cmd.Info.VersionTag=1.0" do not work, so we use
// these separate files so variables can be set from the Makefile.
var (
	versionTag string
	buildTime  string
)

// fscrypt specific initialization
func init() {
	Info.VersionTag = versionTag
	Info.BuildTime = buildTime
	Info.Authors = []cli.Author{{
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

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

	"github.com/blang/semver"
	"github.com/pkg/errors"
)

var (
	// VersionTag (if set) will be displayed in both the short and long
	// version output and can be accessed though Context.Info.Version.
	// VersionTag must be formatted using Semver (http://semver.org/).
	//
	// Often set in Makefile with "-X cmd.VersionTag=$(VERSION)"
	VersionTag string
	// BuildTimeTag (if set) will be displayed in the long version
	// output and can be accessed thought Context.Info.BuildTime. This
	// string must be formatted as the output of UNIX `date`.
	//
	// Often set in Makefile with "-X cmd.BuildTimeTag=$(shell date)"
	BuildTimeTag string
	// Authors (if non-empty) are displayed in the long version output and
	// can be accessed though Context.Info.Authors.
	Authors []Author
	// Copyright (if set) is displayed in the long version output and can
	// be accessed through Context.Info.Copyright.
	Copyright string
)

// fscrypt specific initialization
func init() {
	Authors = []Author{{
		Name:  "Joe Richey",
		Email: "joerichey@google.com",
	}}
	Copyright = `Copyright 2017 Google, Inc.

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

// Creates the Info structure by parsing the above global variables. Panics if
// the variables to parse are in the incorrect format.
func parseInfo() *Info {
	var err error

	var t time.Time
	if BuildTimeTag != "" {
		if t, err = time.Parse(time.UnixDate, BuildTimeTag); err != nil {
			panic(err)
		}
	}

	var v semver.Version
	if VersionTag != "" {
		if v, err = semver.ParseTolerant(VersionTag); err != nil {
			panic(errors.Wrapf(err, "semver: parsing %q", VersionTag))
		}
	}

	return &Info{
		Version:   v,
		BuildTime: t,
		Authors:   Authors,
		Copyright: Copyright,
	}
}

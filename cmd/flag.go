/*
 * flag.go - Definitions for flags and associated formatting functions.
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
	"strconv"
	"time"
)

// Flag represents a flag that can be passed to a command. The Name, ArgName,
// and Usage are used to format and display the flag.
type Flag interface {
	// String formats the flag as either "--name" or "--name=<argName>".
	fmt.Stringer
	// FullUsage is the usage for this flag with an optional default note.
	FullUsage() string
	// Apply sets up this flag on a flag set.
	Apply(*flag.FlagSet)
}

// Formats as "--name" or as "--name=<argName>" if argName is present.
func formatHelper(name, argName string) string {
	if argName != "" {
		return fmt.Sprintf("--%s=<%s>", name, argName)
	}
	return fmt.Sprintf("--%s", name)
}

// Appends (default: <default>) to the usage if defaultString is present.
func usageHelper(usage, defaultString string) string {
	if defaultString != "" {
		usage += fmt.Sprintf(" (default: %s)", defaultString)
	}
	return usage
}

// BoolFlag is a Flag of type bool.
type BoolFlag struct {
	Name    string
	Usage   string
	Default bool
	Value   bool
}

// String always uses the smaller format, as it has no ArgName.
func (f *BoolFlag) String() string { return formatHelper(f.Name, "") }

// FullUsage shows the default if it's true (flag is implicitly passed).
func (f *BoolFlag) FullUsage() string {
	if !f.Default {
		return usageHelper(f.Usage, "")
	}
	return usageHelper(f.Usage, "true")
}

// Apply uses BoolFlag's value to set a flag.BoolVar on the FlagSet.
func (f *BoolFlag) Apply(s *flag.FlagSet) { s.BoolVar(&f.Value, f.Name, f.Default, f.Usage) }

// StringFlag is a Flag of type string.
type StringFlag struct {
	Name    string
	ArgName string
	Usage   string
	Default string
	Value   string
}

func (f *StringFlag) String() string { return formatHelper(f.Name, f.ArgName) }

// FullUsage shows the deafult if the string is non-empty.
func (f *StringFlag) FullUsage() string {
	if f.Default == "" {
		return usageHelper(f.Usage, "")
	}
	return usageHelper(f.Usage, strconv.Quote(f.Default))
}

// Apply uses StringFlag's value to set a flag.StringVar on the FlagSet.
func (f *StringFlag) Apply(s *flag.FlagSet) { s.StringVar(&f.Value, f.Name, f.Default, f.Usage) }

// DurationFlag is a Flag of type time.Duration.
type DurationFlag struct {
	Name    string
	ArgName string
	Usage   string
	Default time.Duration
	Value   time.Duration
}

func (f *DurationFlag) String() string { return formatHelper(f.Name, f.ArgName) }

// FullUsage shows the default if the duration is non-zero.
func (f *DurationFlag) FullUsage() string {
	if f.Default == 0 {
		return usageHelper(f.Usage, "")
	}
	return usageHelper(f.Usage, f.Default.String())
}

// Apply uses DurationFlag's value to set a flag.DurationVar on the FlagSet.
func (f *DurationFlag) Apply(s *flag.FlagSet) { s.DurationVar(&f.Value, f.Name, f.Default, f.Usage) }

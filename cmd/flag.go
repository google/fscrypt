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

// Flag represents a command line flag that can be passed to a command. Note
// that Flag also conforms to the cli.Flag interface. The Name, ArgName, and
// Usage of the Flag can be used to format it in a short form with ShortFormat,
// or in it's full format with the String method.
type Flag interface {
	fmt.Stringer
	Apply(*flag.FlagSet)
	GetName() string
	GetArgName() string
	GetUsage() string
}

// How the first usage line for a Flag should appear. We have two formats:
//  --name
//  --name=<argName>
// The <argName> appears if the prettyFlag's GetArgName() method returns a
// non-empty string. The returned string from shortFormat() does not include
// any leading or trailing whitespace.
func ShortFormat(f Flag) string {
	if argName := f.GetArgName(); argName != "" {
		return fmt.Sprintf("--%s=%s", f.GetName(), argName)
	}
	return fmt.Sprintf("--%s", f.GetName())
}

// How our flags should appear when displaying their usage. An example would be:
//	--help
//		Prints help screen for commands and subcommands.
//
// If defaultString is specified, this if appended to the usage. Example:
//
//	--legacy
//		Allow for support of older kernels with ext4 (before v4.8) and
//		F2FS (before v4.6) filesystems. (default: true)
func longFormat(f Flag, defaultString ...string) string {
	usage := f.GetUsage()
	if len(defaultString) > 0 {
		usage += fmt.Sprintf(" (default: %v)", defaultString[0])
	}

	usage = wrapText(usage, 2)
	return fmt.Sprintf("\t%s\n%s", ShortFormat(f), usage)
}

// BoolFlag is a Flag of type bool.
type BoolFlag struct {
	Name    string
	Usage   string
	Default bool
	Value   bool
}

func (f *BoolFlag) String() string {
	if !f.Default {
		return longFormat(f)
	}
	return longFormat(f, strconv.FormatBool(f.Default))
}

// Apply uses BoolFlag's value to set a flag.BoolVar on the FlagSet.
func (f *BoolFlag) Apply(s *flag.FlagSet) { s.BoolVar(&f.Value, f.Name, f.Default, f.Usage) }

// GetName just returns BoolFlag's name.
func (f *BoolFlag) GetName() string { return f.Name }

// GetArgName returns nothing as BoolFlags don't have an argument name.
func (f *BoolFlag) GetArgName() string { return "" }

// GetUsage returns BoolFlag's usage.
func (f *BoolFlag) GetUsage() string { return f.Usage }

// StringFlag is a Flag of type string.
type StringFlag struct {
	Name    string
	ArgName string
	Usage   string
	Default string
	Value   string
}

func (f *StringFlag) String() string {
	if f.Default == "" {
		return longFormat(f)
	}
	return longFormat(f, strconv.Quote(f.Default))
}

// Apply uses StringFlag's value to set a flag.StringVar on the FlagSet.
func (f *StringFlag) Apply(s *flag.FlagSet) { s.StringVar(&f.Value, f.Name, f.Default, f.Usage) }

// GetName just returns StringFlag's name.
func (f *StringFlag) GetName() string { return f.Name }

// GetArgName returns StringFlag's argument name.
func (f *StringFlag) GetArgName() string { return f.ArgName }

// GetUsage returns StringFlag's usage.
func (f *StringFlag) GetUsage() string { return f.Usage }

// DurationFlag is a Flag of type time.Duration.
type DurationFlag struct {
	Name    string
	ArgName string
	Usage   string
	Default time.Duration
	Value   time.Duration
}

func (f *DurationFlag) String() string {
	if f.Default == 0 {
		return longFormat(f)
	}
	return longFormat(f, f.Default.String())
}

// Apply uses DurationFlag's value to set a flag.DurationVar on the FlagSet.
func (f *DurationFlag) Apply(s *flag.FlagSet) { s.DurationVar(&f.Value, f.Name, f.Default, f.Usage) }

// GetName just returns DurationFlag's name.
func (f *DurationFlag) GetName() string { return f.Name }

// GetArgName returns DurationFlag's argument name.
func (f *DurationFlag) GetArgName() string { return f.ArgName }

// GetUsage returns DurationFlag's usage.
func (f *DurationFlag) GetUsage() string { return f.Usage }

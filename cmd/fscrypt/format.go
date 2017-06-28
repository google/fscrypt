/*
 * format.go - Contains all the functionality for formatting the command line
 * output. This includes formatting the description and flags so that the whole
 * text is <= LineLength characters.
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
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/google/fscrypt/util"
)

var (
	// lineLength is the maximum width of fscrypt's formatted output. It is
	// usually the width of the terminal.
	lineLength         int
	fallbackLineLength = 80 // fallback is punch cards
	maxLineLength      = 120
	// IndentLength is the number spaces to indent by.
	indentLength = 2
	// length of the longest shortDisplay for a flag
	maxShortDisplay int
	// how much the a flag's usage text needs to be moved over
	flagPaddingLength int
)

// We use the init() function to compute our longest short display length. This
// is then used to compute the formatting and padding strings. This ensures we
// will always have room to display our flags, and the flag descriptions always
// appear in the same place.
func init() {
	for _, flag := range allFlags {
		displayLength := utf8.RuneCountInString(shortDisplay(flag))
		if displayLength > maxShortDisplay {
			maxShortDisplay = displayLength
		}
	}

	// Pad usage enough so the flags have room.
	flagPaddingLength = maxShortDisplay + 2*indentLength

	// We use the width of the terminal unless we cannot get the width.
	width, _, err := terminal.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		lineLength = fallbackLineLength
	} else {
		lineLength = util.MinInt(width, maxLineLength)
	}

}

// Flags that conform to this interface can be used with an urfave/cli
// application and can be printed in the correct format.
type prettyFlag interface {
	cli.Flag
	GetArgName() string
	GetUsage() string
}

// How a flag should appear on the command line. We have two formats:
//  --name
//  --name=ARG_NAME
// The ARG_NAME appears if the prettyFlag's GetArgName() method returns a
// non-empty string. The returned string from shortDisplay() does not include
// any leading or trailing whitespace.
func shortDisplay(f prettyFlag) string {
	if argName := f.GetArgName(); argName != "" {
		return fmt.Sprintf("--%s=%s", f.GetName(), argName)
	}
	return fmt.Sprintf("--%s", f.GetName())
}

// How our flags should appear when displaying their usage. An example would be:
//
//  --help                     Prints help screen for commands and subcommands.
//
// If a default is specified, this if appended to the usage. Example:
//
//  --legacy                   Allow for support of older kernels with ext4
//                             (before v4.8) and F2FS (before v4.6) filesystems.
//                             (default: true)
//
func longDisplay(f prettyFlag, defaultString ...string) string {
	usage := f.GetUsage()
	if len(defaultString) > 0 {
		usage += fmt.Sprintf(" (default: %v)", defaultString[0])
	}

	// We pad the the shortDisplay on the right with enough spaces to equal
	// the longest flag's display
	shortDisp := shortDisplay(f)
	length := utf8.RuneCountInString(shortDisp)
	shortDisp += strings.Repeat(" ", maxShortDisplay-length)

	return indent + shortDisp + indent + wrapText(usage, flagPaddingLength)
}

// Regex that determines if we are starting an ordered list
var listRegex = regexp.MustCompile(`^\([\d]+\)$`)

// Takes an input string text, and wraps the text so that each line begins with
// padding spaces (except for the first line), ends with a newline (except the
// last line), and each line has length less than lineLength. If the text
// contains a word which is too long, that word gets its own line.
func wrapText(text string, padding int) string {
	// We use a buffer to format the wrapped text so we get O(n) runtime
	var buffer bytes.Buffer
	spaceLeft := 0
	maxTextLen := lineLength - padding
	delimiter := strings.Repeat(" ", padding)
	for i, word := range strings.Fields(text) {
		wordLen := utf8.RuneCountInString(word)
		switch {
		case i == 0:
			// No delimiter for the first line
			buffer.WriteString(word)
			spaceLeft = maxTextLen - wordLen
		case listRegex.Match([]byte(word)):
			// Add an additional line to separate list items.
			buffer.WriteString("\n")
			fallthrough
		case wordLen+1 > spaceLeft:
			// If no room left, write the word on the next line.
			buffer.WriteString("\n")
			buffer.WriteString(delimiter)
			buffer.WriteString(word)
			spaceLeft = maxTextLen - wordLen
		default:
			// Write word on this line
			buffer.WriteByte(' ')
			buffer.WriteString(word)
			spaceLeft -= 1 + wordLen
		}
	}

	return buffer.String()
}

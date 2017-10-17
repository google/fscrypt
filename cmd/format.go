/*
 * format.go - Functions for handling output formatting.
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
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"
	"unicode/utf8"

	"github.com/google/fscrypt/util"
	"golang.org/x/crypto/ssh/terminal"
)

// Suffixes for questions with a yes or no default
const (
	defaultYesSuffix = "[Y/n]"
	defaultNoSuffix  = "[y/N]"
)

// Variables which control how output is formmatted and where it goes.
var (
	// TabWidth is the number of spaces used to display a tab.
	TabWidth = 8
	// LineLength is the maximum length of any output. If not set, the width
	// of the terminal be detected and assigned to LineLength.
	LineLength int
	// FallbackLineLength is the LineLength used if detection fails. By
	// default we fall back to punch cards.
	FallbackLineLength = 80
	// MaxLineLength is the maximum allowed detected value of LineLength.
	MaxLineLength = 120
	// Output is the io.Writer all commands should use for their normal
	// output (errors should just return the appropriate error). If not set,
	// it is automatically set based on the provided flags.
	Output io.Writer
)

// We use the width of the terminal unless we cannot get the width.
func init() {
	if LineLength > 0 {
		return
	}
	width, _, err := terminal.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		LineLength = FallbackLineLength
	} else {
		LineLength = util.MinInt(width, MaxLineLength)
	}
}

// WrapText wraps an input string so that each line begins with numTabs tabs
// (except the first line) and ends with a newline (except the last line), and
// each line has length less than lineLength. If the text contains a word which
// is too long, that word gets its own line.
func WrapText(text string, numTabs int) string {
	// We use a buffer to format the wrapped text so we get O(n) runtime
	var buffer bytes.Buffer
	spaceLeft := 0
	maxTextLen := LineLength - numTabs*TabWidth
	delimiter := strings.Repeat("\t", numTabs)
	for i, word := range strings.Fields(text) {
		wordLen := utf8.RuneCountInString(word)
		if i == 0 {
			buffer.WriteString(word)
			spaceLeft = maxTextLen - wordLen
		} else if wordLen >= spaceLeft {
			// If no room left, write the word on the next line.
			buffer.WriteString("\n")
			buffer.WriteString(delimiter)
			buffer.WriteString(word)
			spaceLeft = maxTextLen - wordLen
		} else {
			// Write word on this line
			buffer.WriteByte(' ')
			buffer.WriteString(word)
			spaceLeft -= 1 + wordLen
		}
	}

	return buffer.String()
}

// Add words to this map if pluralization does not just involve adding an s.
var plurals = map[string]string{
	"policy": "policies",
}

// Pluralize returns the correct pluralization of a work along with the
// specified count. This means Pluralize(1, "policy") = "1 policy" but
// Pluralize(2, "policy") = "2 policies".
func Pluralize(count int, word string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, word)
	}
	if plural, ok := plurals[word]; ok {
		return fmt.Sprintf("%d %s", count, plural)
	}
	return fmt.Sprintf("%d %ss", count, word)
}

// AskQuestion asks the user a yes or no question. Returning a boolean on a
// successful answer and an error if there was not a response from the user.
// Returns the defaultChoice on empty input (or in quiet mode).
func AskQuestion(question string, defaultChoice bool) (bool, error) {
	// If in quiet mode, we just use the default.
	if QuietFlag.Value {
		return defaultChoice, nil
	}
	// Loop until failure or valid input.
	for {
		if defaultChoice {
			fmt.Fprintf(Output, "%s %s ", question, defaultYesSuffix)
		} else {
			fmt.Fprintf(Output, "%s %s ", question, defaultNoSuffix)
		}

		input, err := util.ReadLine()
		if err != nil {
			return false, err
		}

		switch strings.ToLower(input) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		case "":
			return defaultChoice, nil
		}
	}
}

// AskConfirmation asks the user for confirmation before performing a specific
// action. An error is returned if the user declines or IO fails.
func AskConfirmation(question, warning string, defaultChoice bool) error {
	// All confirmations are "yes" if we are forcing.
	if ForceFlag.Value {
		return nil
	}

	// Defaults of "no" require forcing.
	if QuietFlag.Value {
		if defaultChoice {
			return nil
		}
		return ErrMustForce
	}

	if warning != "" {
		fmt.Fprintln(Output, WrapText("WARNING: "+warning, 0))
	}

	confirmed, err := AskQuestion(question, defaultChoice)
	if err != nil {
		return err
	}
	if !confirmed {
		return ErrCanceled
	}
	return nil
}

// ExecuteTemplate creates an anonymous template from the text, and runs it with
// the provided Context and writer. Panics if text cannot be executed.
func ExecuteTemplate(w io.Writer, text string, ctx *Context) {
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"WrapText": WrapText,
	}).Parse(text))
	if err := tmpl.Execute(w, ctx); err != nil {
		panic(err)
	}
}

/*
 * output.go - Functions for handling command line formatting and output.
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
	"io/ioutil"
	"log"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/google/fscrypt/util"
	"golang.org/x/crypto/ssh/terminal"
)

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
	// HelpFlag writes help to Stdout
	HelpFlag = &BoolFlag{
		Name:  "help",
		Usage: "Prints this help text for commands and subcommands",
	}
	// VerboseFlag indicates that all logging output should be printed.
	VerboseFlag = &BoolFlag{
		Name:  "verbose",
		Usage: "Prints additional debug messages.",
	}
	// QuietFlag indicates that no normal output should be printed.
	QuietFlag = &BoolFlag{
		Name: "quiet",
		Usage: `Prints nothing except for errors and uses any default
		option instead of prompting the user.`,
	}
	// ForceFlag indicates that the operation should proceed if possible.
	ForceFlag = &BoolFlag{
		Name: "force",
		Usage: `Print no confirmation prompts or warnings and
		automatically proceed with the requested action.`,
	}
)

// Suffixes for questions with a yes or no default
const (
	defaultYesSuffix = "[Y/n]"
	defaultNoSuffix  = "[y/N]"
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

// Takes an input string text, and wraps the text so that each line begins with
// numTabs tabs and ends with a newline (except the last line), and each line
// has length less than lineLength. If the text contains a word which is too
// long, that word gets its own line.
func wrapText(text string, numTabs int) string {
	// We use a buffer to format the wrapped text so we get O(n) runtime
	var buffer bytes.Buffer
	spaceLeft := 0
	maxTextLen := LineLength - numTabs*TabWidth
	delimiter := strings.Repeat("\t", numTabs)
	for _, word := range strings.Fields(text) {
		wordLen := utf8.RuneCountInString(word)
		if wordLen >= spaceLeft {
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

// Configures the Output and log output io.Writers. Called before running
// commands but after processing flags.
func setupOutput() {
	if VerboseFlag.Value {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(ioutil.Discard)
	}
	if Output != nil {
		return
	}
	if QuietFlag.Value {
		Output = ioutil.Discard
	} else {
		Output = os.Stdout
	}
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
		fmt.Fprintln(Output, wrapText("WARNING: "+warning, 0))
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

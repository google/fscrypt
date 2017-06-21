/*
 * prompt.go - Functions for handling user input and options
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
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"

	"fscrypt/actions"
	"fscrypt/metadata"
)

const (
	// Suffixes for questions with a yes or no default
	defaultYesSuffix = " [Y/n] "
	defaultNoSuffix  = " [y/N] "
)

// Descriptions for each of the protector sources
var sourceDescriptions = map[metadata.SourceType]string{
	metadata.SourceType_pam_passphrase:    "Your login passphrase",
	metadata.SourceType_custom_passphrase: "A custom passphrase",
	metadata.SourceType_raw_key:           "A raw 256-bit key",
}

// promptUser presents a message to the user and returns their input string. An
// error is returned if our read from standard input fails.
func promptUser(prompt string) (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print(prompt)
	if !scanner.Scan() {
		return "", ErrReadingStdin
	}
	return scanner.Text(), nil
}

// askQuestion asks the user a yes or no question. Returning a boolean on a
// successful answer and an error if there was not a response from the user.
// Returns the defaultChoice on empty input (or in quiet mode).
func askQuestion(question string, defaultChoice bool) (bool, error) {
	// If in quiet mode, we just use the default
	if quietFlag.Value {
		return defaultChoice, nil
	}
	// Loop until failure or valid input
	var input string
	var err error
	for {
		if defaultChoice {
			input, err = promptUser(question + defaultYesSuffix)
		} else {
			input, err = promptUser(question + defaultNoSuffix)
		}
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

// askConfirmation asks the user for confirmation of a specific action. An error
// is returned if the user declines or IO fails.
func askConfirmation(question string, defaultChoice bool, warning string) error {
	// All confirmations are "yes" if we are forcing.
	if forceFlag.Value {
		return nil
	}

	// Defaults of "no" require forcing.
	if !defaultChoice {
		if quietFlag.Value {
			return ErrNoDesctructiveOps
		}
	}

	if warning != "" && !quietFlag.Value {
		fmt.Println(wrapText("WARNING: "+warning, 0))
	}

	confirmed, err := askQuestion(question, defaultChoice)
	if err != nil {
		return err
	}
	if !confirmed {
		return ErrCanceled
	}
	return nil
}

// getUsername returns the username for the provided UID. If the UID does not
// correspond to a user or the username is blank, "UID=<uid>" is returned.
func getUsername(uid int64) string {
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil || u.Username == "" {
		return fmt.Sprintf("UID=%d", uid)
	}
	return u.Username
}

// formatInfo gives a string description of metadata.ProtectorData.
func formatInfo(data actions.ProtectorInfo) string {
	switch data.Source() {
	case metadata.SourceType_pam_passphrase:
		return "login protector for " + getUsername(data.UID())
	case metadata.SourceType_custom_passphrase:
		return fmt.Sprintf("custom protector %q", data.Name())
	case metadata.SourceType_raw_key:
		return fmt.Sprintf("raw key protector %q", data.Name())
	default:
		panic(ErrInvalidSource)
	}
}

// promptForName gets a name from user input (or flags) and returns it.
func promptForName(ctx *actions.Context) (string, error) {
	// A name flag means we do not need to prompt
	if nameFlag.Value != "" {
		return nameFlag.Value, nil
	}

	// Don't ask for a name if we do not need it
	if quietFlag.Value || ctx.Config.Source == metadata.SourceType_pam_passphrase {
		return "", nil
	}

	for {
		name, err := promptUser("Enter a name for the new protector: ")
		if err != nil {
			return "", err
		}
		if name != "" {
			return name, nil
		}
	}
}

// promptForSource gets a source type from user input (or flags) and modifies
// the context to use that source.
func promptForSource(ctx *actions.Context) error {
	// A source flag overrides everything else.
	if sourceFlag.Value != "" {
		val, ok := metadata.SourceType_value[sourceFlag.Value]
		if !ok || val == 0 {
			return ErrInvalidSource
		}
		ctx.Config.Source = metadata.SourceType(val)
		return nil
	}

	// Just use the default in quiet mode
	if quietFlag.Value {
		return nil
	}

	// We print all the sources with their number, description, and name.
	fmt.Println("Your data can be protected with one of the following sources:")
	for idx := 1; idx < len(metadata.SourceType_value); idx++ {
		source := metadata.SourceType(idx)
		description := sourceDescriptions[source]
		fmt.Printf("%d - %s (%s)\n", idx, description, source)
	}

	prompt := fmt.Sprintf("Enter the source number for the new protector [%d - %s]: ",
		ctx.Config.Source, ctx.Config.Source)
	for {
		input, err := promptUser(prompt)
		if err != nil {
			return err
		}

		// Use the default if the user just hits enter
		if input == "" {
			return nil
		}

		// Check for a valid index, reprompt if invalid.
		index, err := strconv.Atoi(input)
		if err == nil && index >= 1 && index < len(metadata.SourceType_value) {
			ctx.Config.Source = metadata.SourceType(index)
			return nil
		}
	}
}

// promptForKeyFile returns an open file that should be used to create or unlock
// a raw_key protector. Be sure to close the file when done.
func promptForKeyFile(prompt string) (*os.File, error) {
	// If specified on the command line, we only try no open it once.
	if keyFileFlag.Value != "" {
		return os.Open(keyFileFlag.Value)
	}
	if quietFlag.Value {
		return nil, ErrSpecifyKeyFile
	}

	// Prompt for a valid path until we get a file we can open.
	for {
		filename, err := promptUser(prompt)
		if err != nil {
			return nil, err
		}
		file, err := os.Open(filename)
		if err == nil {
			return file, nil
		}
		fmt.Println(err)
	}

}

// promptForProtector, given a non-empty list of protector options, uses user
// input to select the desired protector. If there is only one option to choose
// from, that protector is automatically selected.
func promptForProtector(options []*actions.ProtectorOption) (int, error) {
	numOptions := len(options)
	log.Printf("selecting from %s", pluralize(numOptions, "protector"))

	// Get the number of load errors.
	numLoadErrors := 0
	for _, option := range options {
		if option.LoadError != nil {
			log.Printf("when loading option: %v", option.LoadError)
			numLoadErrors++
		}
	}

	if numLoadErrors == numOptions {
		return 0, ErrAllLoadsFailed
	}
	if numOptions == 1 {
		return 0, nil
	}
	if quietFlag.Value {
		return 0, ErrSpecifyProtector
	}

	// List all of the protector options which did not have a load error.
	fmt.Println("The available protectors are: ")
	for idx, option := range options {
		if option.LoadError != nil {
			continue
		}

		description := fmt.Sprintf("%d - %s", idx, formatInfo(option.ProtectorInfo))
		if option.LinkedMount != nil {
			description += fmt.Sprintf(" (linked protector on %q)", option.LinkedMount.Path)
		}
		fmt.Println(description)
	}

	if numLoadErrors > 0 {
		fmt.Printf(wrapText("NOTE: %d of the %d protectors failed to load. "+loadHelpText, 0))
	}

	for {
		input, err := promptUser("Enter the number of protector to use: ")
		if err != nil {
			return 0, err
		}

		// Check for a valid index, reprompt if invalid.
		index, err := strconv.Atoi(input)
		if err == nil && index >= 0 && index < len(options) {
			return index, nil
		}
	}
}

// optionFn is an actions.OptionFunc which handles selecting an option for a
// specific policy. This is either done interactively, or by deferring to the
// protectorFlag.
func optionFn(policyDescriptor string, options []*actions.ProtectorOption) (int, error) {
	// If we have an unlock-with flag, we directly select the specified
	// protector to unlock the policy.
	if unlockWithFlag.Value != "" {
		log.Printf("optionFn(%s) w/ unlock flag", policyDescriptor)
		protector, err := getProtectorFromFlag(unlockWithFlag.Value)
		if err != nil {
			return 0, err
		}

		for idx, option := range options {
			if option.Descriptor() == protector.Descriptor() {
				return idx, nil
			}
		}
		return 0, actions.ErrNotProtected
	}

	log.Printf("optionFn(%s)", policyDescriptor)
	return promptForProtector(options)
}

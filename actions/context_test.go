/*
 * context_test.go - tests for creating new contexts
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

package actions

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/fscrypt/util"
	"github.com/pkg/errors"
)

const testTime = 10 * time.Millisecond

// holds the context we will use throughout the actions tests
var testContext *Context

// Makes a context using the testing locations for the filesystem and
// configuration file.
func setupContext() (ctx *Context, err error) {
	mountpoint, err := util.TestRoot()
	if err != nil {
		return nil, err
	}

	ConfigFileLocation = filepath.Join(mountpoint, "test.conf")

	// Should not be able to setup without a config file
	if badCtx, badCtxErr := NewContextFromMountpoint(mountpoint, nil); badCtxErr == nil {
		badCtx.Mount.RemoveAllMetadata()
		return nil, fmt.Errorf("created context at %q without config file", badCtx.Mount.Path)
	}

	if err = CreateConfigFile(testTime); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(ConfigFileLocation)
		}
	}()

	ctx, err = NewContextFromMountpoint(mountpoint, nil)
	if err != nil {
		return nil, err
	}

	return ctx, ctx.Mount.Setup()
}

// Cleans up the testing config file and testing filesystem data.
func cleaupContext(ctx *Context) error {
	err1 := os.RemoveAll(ConfigFileLocation)
	err2 := ctx.Mount.RemoveAllMetadata()
	if err1 != nil {
		return err1
	}
	return err2
}

func TestMain(m *testing.M) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	var err error
	testContext, err = setupContext()
	if err != nil {
		fmt.Println(err)
		if errors.Cause(err) != util.ErrSkipIntegration {
			os.Exit(1)
		}
		os.Exit(0)
	}

	returnCode := m.Run()
	err = cleaupContext(testContext)
	if err != nil {
		fmt.Printf("cleanupContext() = %v\n", err)
		os.Exit(1)
	}
	os.Exit(returnCode)
}

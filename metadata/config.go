/*
 * config.go - Parsing for our global config file. The file is simply the JSON
 * output of the Config protocol buffer.
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

// Package metadata contains all of the on disk structures.
// These structures are definied in meatadata.proto. The package also
// contains functions for reading and writing the Config file to disk
// giving us a config file.
package metadata

//go:generate protoc --go_out=. metadata.proto
import "github.com/golang/protobuf/jsonpb"

// WriteConfig outputs the Config data as nicely formatted JSON
func WriteConfig(config *Config) (string, error) {
	m := jsonpb.Marshaler{
		EmitDefaults: false,
		EnumsAsInts:  false,
		Indent:       "\t",
		OrigName:     true,
	}
	return m.MarshalToString(config)
}

// ReadConfig writes the JSON data into the config structure
func ReadConfig(input string) (*Config, error) {
	config := new(Config)
	return config, jsonpb.UnmarshalString(input, config)
}

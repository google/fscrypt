/*
 * strings.go - Strings and templates for output formatting
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
	"io"
	"text/template"
)

// ExecuteTemplate creates an anonymous template the text, and runs it with the
// provided writer and data. Panics if text has bad format or execution fails.
func ExecuteTemplate(w io.Writer, text string, data interface{}) {
	tmpl := template.Must(template.New("").Parse(text))
	if err := tmpl.Execute(w, data); err != nil {
		panic(err)
	}
}

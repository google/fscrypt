/*
 * cgroup_test.go - Tests for cgroup CPU and memory limit reading.
 *
 * Copyright 2026 Google LLC
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

package cgroup

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupV1Unsupported(t *testing.T) {
	content := `12:memory:/docker/abc123
11:cpu,cpuacct:/docker/abc123
`
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/self/cgroup"), content)
	_, err := NewFromRoot(root)
	if !errors.Is(err, ErrV1Detected) {
		t.Fatalf("NewFromRoot() error = %v, want %v", err, ErrV1Detected)
	}
}

// testdataExpected holds the expected values from a testdata/*/expected.json.
// Null fields indicate that ErrNoLimit is expected.
type testdataExpected struct {
	CPUQuota    *float64 `json:"cpu_quota"`
	MemoryLimit *int64   `json:"memory_limit"`
}

// TestWithRootFromTestdata runs NewFromRoot, CPUQuota, and MemoryLimit
// against filesystem snapshots captured from real Docker containers by
// bin/snapshot-cgroup. Each subdirectory of testdata/ is a separate test
// case containing a proc/ and sys/ tree plus an expected.json.
//
// Regenerate with: bin/gen-cgroup-testdata
func TestWithRootFromTestdata(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("no testdata directory: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		root := filepath.Join("testdata", name)

		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, "expected.json"))
			if err != nil {
				t.Fatalf("reading expected.json: %v", err)
			}
			var want testdataExpected
			if err := json.Unmarshal(data, &want); err != nil {
				t.Fatalf("parsing expected.json: %v", err)
			}

			cg, err := NewFromRoot(root)
			if err != nil {
				t.Fatalf("NewFromRoot(%q): %v", root, err)
			}

			gotCPU, err := cg.CPUQuota()
			if want.CPUQuota == nil {
				if !errors.Is(err, ErrNoLimit) {
					t.Errorf("CPUQuota() error = %v, want ErrNoLimit", err)
				}
			} else if err != nil {
				t.Fatalf("CPUQuota(): %v", err)
			} else if math.Abs(gotCPU-*want.CPUQuota) > 0.001 {
				t.Errorf("CPUQuota() = %v, want %v", gotCPU, *want.CPUQuota)
			}

			gotMem, err := cg.MemoryLimit()
			if want.MemoryLimit == nil {
				if !errors.Is(err, ErrNoLimit) {
					t.Errorf("MemoryLimit() error = %v, want ErrNoLimit", err)
				}
			} else if err != nil {
				t.Fatalf("MemoryLimit(): %v", err)
			} else if gotMem != *want.MemoryLimit {
				t.Errorf("MemoryLimit() = %v, want %v", gotMem, *want.MemoryLimit)
			}
		})
	}
}

// TestIntegrationCgroupLimits calls the real New(), CPUQuota(), and
// MemoryLimit() against the live kernel cgroup interface. It is intended to
// run inside a Docker container started with --cpus and --memory flags.
//
// The test is skipped unless CGROUP_EXPECTED_CPU_QUOTA and
// CGROUP_EXPECTED_MEMORY_LIMIT are set in the environment.
func TestIntegrationCgroupLimits(t *testing.T) {
	cpuStr := os.Getenv("CGROUP_EXPECTED_CPU_QUOTA")
	memStr := os.Getenv("CGROUP_EXPECTED_MEMORY_LIMIT")
	if cpuStr == "" && memStr == "" {
		t.Skip("set CGROUP_EXPECTED_CPU_QUOTA and CGROUP_EXPECTED_MEMORY_LIMIT to run")
	}

	cg, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if cpuStr != "" {
		wantCPU, err := strconv.ParseFloat(cpuStr, 64)
		if err != nil {
			t.Fatalf("bad CGROUP_EXPECTED_CPU_QUOTA %q: %v", cpuStr, err)
		}
		gotCPU, err := cg.CPUQuota()
		if err != nil {
			t.Fatalf("CPUQuota() error: %v", err)
		}
		if math.Abs(gotCPU-wantCPU) > 0.001 {
			t.Errorf("CPUQuota() = %v, want %v", gotCPU, wantCPU)
		}
	}

	if memStr != "" {
		wantMem, err := strconv.ParseInt(memStr, 10, 64)
		if err != nil {
			t.Fatalf("bad CGROUP_EXPECTED_MEMORY_LIMIT %q: %v", memStr, err)
		}
		gotMem, err := cg.MemoryLimit()
		if err != nil {
			t.Fatalf("MemoryLimit() error: %v", err)
		}
		if gotMem != wantMem {
			t.Errorf("MemoryLimit() = %v, want %v", gotMem, wantMem)
		}
	}
}

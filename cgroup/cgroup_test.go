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
	"strings"
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

func TestParseCPUMax(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    float64
		wantErr string
	}{
		{"half core", "50000 100000", 0.5, ""},
		{"two cores", "200000 100000", 2.0, ""},
		{"quota only with default period", "50000", 0.5, ""},
		{"unlimited", "max 100000", 0, "no cgroup limit set"},
		{"empty", "", 0, "unexpected cpu.max format"},
		{"zero period", "50000 0", 0, "period is zero"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCPUMax(tt.content)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseCPUMax(%q) error = %v, want error containing %q", tt.content, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCPUMax(%q) unexpected error: %v", tt.content, err)
			}
			if math.Abs(got-tt.want) > 0.001 {
				t.Errorf("parseCPUMax(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}

func TestParseMemoryMax(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int64
		wantErr string
	}{
		{"128 MiB", "134217728", 134217728, ""},
		{"unlimited", "max", 0, "no cgroup limit set"},
		{"invalid", "abc", 0, "parsing memory.max"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMemoryMax(tt.content)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseMemoryMax(%q) error = %v, want error containing %q", tt.content, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMemoryMax(%q) unexpected error: %v", tt.content, err)
			}
			if got != tt.want {
				t.Errorf("parseMemoryMax(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}

func TestParseProcCgroup(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantGroup string
		wantErr   string
	}{
		{
			name:      "cgroup v2",
			content:   "0::/user.slice/user-1000.slice/session-1.scope\n",
			wantGroup: "/user.slice/user-1000.slice/session-1.scope",
		},
		{
			name:    "v1 only (no v2 entry)",
			content: "12:memory:/docker/abc123\n11:cpu,cpuacct:/docker/abc123\n",
			wantErr: "no cgroup v2 entry",
		},
		{
			name:      "hybrid v1 and v2",
			content:   "12:memory:/docker/abc123\n0::/docker/abc123\n",
			wantGroup: "/docker/abc123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "cgroup")
			writeFile(t, f, tt.content)

			groupPath, err := parseProcCgroup(f)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseProcCgroup() error = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if groupPath != tt.wantGroup {
				t.Errorf("parseProcCgroup() = %q, want %q", groupPath, tt.wantGroup)
			}
		})
	}
}

func TestCPUQuotaV2(t *testing.T) {
	tests := []struct {
		name    string
		cpuMax  string
		want    float64
		wantErr string
	}{
		{"half core", "50000 100000\n", 0.5, ""},
		{"four cores", "400000 100000\n", 4.0, ""},
		{"unlimited", "max 100000\n", 0, "no cgroup limit set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "cpu.max"), tt.cpuMax)

			got, err := cpuQuotaV2(dir)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if math.Abs(got-tt.want) > 0.001 {
				t.Errorf("cpuQuotaV2() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCPUQuotaV2MissingFile(t *testing.T) {
	_, err := cpuQuotaV2(t.TempDir())
	if !errors.Is(err, ErrNoLimit) {
		t.Errorf("error = %v, want ErrNoLimit", err)
	}
}

func TestMemoryLimitV2(t *testing.T) {
	tests := []struct {
		name      string
		memoryMax string
		want      int64
		wantErr   string
	}{
		{"128 MiB", "134217728\n", 134217728, ""},
		{"unlimited", "max\n", 0, "no cgroup limit set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "memory.max"), tt.memoryMax)

			got, err := memoryLimitV2(dir)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("memoryLimitV2() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMemoryLimitV2MissingFile(t *testing.T) {
	_, err := memoryLimitV2(t.TempDir())
	if !errors.Is(err, ErrNoLimit) {
		t.Errorf("error = %v, want ErrNoLimit", err)
	}
}

func TestCPUQuotaWithRoot(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "proc/self/cgroup"), "0::/kubepods/pod123\n")
	writeFile(t, filepath.Join(root, "sys/fs/cgroup/kubepods/pod123/cpu.max"), "50000 100000\n")

	got, err := CPUQuotaWithRoot(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.Abs(got-0.5) > 0.001 {
		t.Errorf("CPUQuotaWithRoot() = %v, want 0.5", got)
	}
}

func TestMemoryLimitWithRoot(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "proc/self/cgroup"), "0::/kubepods/pod123\n")
	writeFile(t, filepath.Join(root, "sys/fs/cgroup/kubepods/pod123/memory.max"), "134217728\n")

	got, err := MemoryLimitWithRoot(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 134217728 {
		t.Errorf("MemoryLimitWithRoot() = %v, want 134217728", got)
	}
}

// testdataExpected holds the expected values from a testdata/*/expected.json.
// Null fields indicate that ErrNoLimit is expected.
type testdataExpected struct {
	CPUQuota    *float64 `json:"cpu_quota"`
	MemoryLimit *int64   `json:"memory_limit"`
}

// TestWithRootFromTestdata runs CPUQuotaWithRoot and MemoryLimitWithRoot
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

			gotCPU, err := CPUQuotaWithRoot(root)
			if want.CPUQuota == nil {
				if !errors.Is(err, ErrNoLimit) {
					t.Errorf("CPUQuotaWithRoot() error = %v, want ErrNoLimit", err)
				}
			} else if err != nil {
				t.Fatalf("CPUQuotaWithRoot(%q): %v", root, err)
			} else if math.Abs(gotCPU-*want.CPUQuota) > 0.001 {
				t.Errorf("CPUQuotaWithRoot() = %v, want %v", gotCPU, *want.CPUQuota)
			}

			gotMem, err := MemoryLimitWithRoot(root)
			if want.MemoryLimit == nil {
				if !errors.Is(err, ErrNoLimit) {
					t.Errorf("MemoryLimitWithRoot() error = %v, want ErrNoLimit", err)
				}
			} else if err != nil {
				t.Fatalf("MemoryLimitWithRoot(%q): %v", root, err)
			} else if gotMem != *want.MemoryLimit {
				t.Errorf("MemoryLimitWithRoot() = %v, want %v", gotMem, *want.MemoryLimit)
			}
		})
	}
}

// TestIntegrationCgroupLimits calls the real CPUQuota() and MemoryLimit()
// functions against the live kernel cgroup interface. It is intended to run
// inside a Docker container started with --cpus and --memory flags.
//
// The test is skipped unless CGROUP_EXPECTED_CPU_QUOTA and
// CGROUP_EXPECTED_MEMORY_LIMIT are set in the environment.
func TestIntegrationCgroupLimits(t *testing.T) {
	cpuStr := os.Getenv("CGROUP_EXPECTED_CPU_QUOTA")
	memStr := os.Getenv("CGROUP_EXPECTED_MEMORY_LIMIT")
	if cpuStr == "" && memStr == "" {
		t.Skip("set CGROUP_EXPECTED_CPU_QUOTA and CGROUP_EXPECTED_MEMORY_LIMIT to run")
	}

	if cpuStr != "" {
		wantCPU, err := strconv.ParseFloat(cpuStr, 64)
		if err != nil {
			t.Fatalf("bad CGROUP_EXPECTED_CPU_QUOTA %q: %v", cpuStr, err)
		}
		gotCPU, err := CPUQuota()
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
		gotMem, err := MemoryLimit()
		if err != nil {
			t.Fatalf("MemoryLimit() error: %v", err)
		}
		if gotMem != wantMem {
			t.Errorf("MemoryLimit() = %v, want %v", gotMem, wantMem)
		}
	}
}

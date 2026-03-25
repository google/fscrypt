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

func TestParseMountInfoLine(t *testing.T) {
	tests := []struct {
		name         string
		line         string
		wantFSType   string
		wantRoot     string
		wantMount    string
		wantSuperOpt string
		wantErr      bool
	}{
		{
			name:         "cgroup v1 cpu",
			line:         "35 26 0:30 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpu,cpuacct",
			wantFSType:   "cgroup",
			wantRoot:     "/",
			wantMount:    "/sys/fs/cgroup/cpu,cpuacct",
			wantSuperOpt: "cpu",
		},
		{
			name:         "cgroup v2",
			line:         "30 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot",
			wantFSType:   "cgroup2",
			wantRoot:     "/",
			wantMount:    "/sys/fs/cgroup",
			wantSuperOpt: "nsdelegate",
		},
		{
			name:    "too short",
			line:    "a b c",
			wantErr: true,
		},
		{
			name:    "no separator",
			line:    "35 26 0:30 / /mnt rw,relatime shared:1 cgroup cgroup rw",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMountInfoLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.fsType != tt.wantFSType {
				t.Errorf("fsType = %q, want %q", got.fsType, tt.wantFSType)
			}
			if got.root != tt.wantRoot {
				t.Errorf("root = %q, want %q", got.root, tt.wantRoot)
			}
			if got.mountPoint != tt.wantMount {
				t.Errorf("mountPoint = %q, want %q", got.mountPoint, tt.wantMount)
			}
			found := false
			for _, opt := range got.superOptions {
				if opt == tt.wantSuperOpt {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("superOptions = %v, want to contain %q", got.superOptions, tt.wantSuperOpt)
			}
		})
	}
}

func TestParseProcCgroup(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		wantVersion    int
		wantGroup      string
		wantSubsystems map[string]string
	}{
		{
			name:        "cgroup v2",
			content:     "0::/user.slice/user-1000.slice/session-1.scope\n",
			wantVersion: 2,
			wantGroup:   "/user.slice/user-1000.slice/session-1.scope",
		},
		{
			name:        "cgroup v1 only",
			content:     "12:memory:/docker/abc123\n11:cpu,cpuacct:/docker/abc123\n",
			wantVersion: 1,
			wantSubsystems: map[string]string{
				"memory":  "/docker/abc123",
				"cpu":     "/docker/abc123",
				"cpuacct": "/docker/abc123",
			},
		},
		{
			name:        "hybrid v1 and v2",
			content:     "12:memory:/docker/abc123\n0::/docker/abc123\n",
			wantVersion: 1,
			wantSubsystems: map[string]string{
				"memory": "/docker/abc123",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "cgroup")
			writeFile(t, f, tt.content)

			cg, err := parseProcCgroup(f)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cg.version != tt.wantVersion {
				t.Errorf("version = %d, want %d", cg.version, tt.wantVersion)
			}
			if tt.wantVersion == 2 && cg.v2GroupPath != tt.wantGroup {
				t.Errorf("v2GroupPath = %q, want %q", cg.v2GroupPath, tt.wantGroup)
			}
			for k, want := range tt.wantSubsystems {
				got, ok := cg.v1Subsystems[k]
				if !ok {
					t.Errorf("v1Subsystems missing key %q", k)
				} else if got != want {
					t.Errorf("v1Subsystems[%q] = %q, want %q", k, got, want)
				}
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

// setupV1Root creates a mock cgroup v1 filesystem under a temp directory.
// The mountinfo file contains absolute paths (as the kernel writes them),
// and the code prepends root when reading.
func setupV1Root(t *testing.T, subsystem, cgroupRelPath string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()

	// /proc/self/cgroup
	var cgroupLine string
	switch subsystem {
	case "cpu":
		cgroupLine = "11:cpu,cpuacct:" + cgroupRelPath + "\n"
	case "memory":
		cgroupLine = "12:memory:" + cgroupRelPath + "\n"
	}
	writeFile(t, filepath.Join(root, "proc/self/cgroup"), cgroupLine)

	// /proc/self/mountinfo with absolute mount point
	mountPoint := "/sys/fs/cgroup/" + subsystem
	mountInfoLine := "35 26 0:30 / " + mountPoint + " rw,nosuid - cgroup cgroup rw," + subsystem + "\n"
	writeFile(t, filepath.Join(root, "proc/self/mountinfo"), mountInfoLine)

	// cgroup control files under root + mountPoint + cgroupRelPath
	cgroupDir := filepath.Join(root, mountPoint, cgroupRelPath)
	for name, content := range files {
		writeFile(t, filepath.Join(cgroupDir, name), content)
	}

	return root
}

func TestCPUQuotaV1(t *testing.T) {
	tests := []struct {
		name    string
		quota   string
		period  string
		want    float64
		wantErr string
	}{
		{"half core", "50000\n", "100000\n", 0.5, ""},
		{"two cores", "200000\n", "100000\n", 2.0, ""},
		{"unlimited", "-1\n", "100000\n", 0, "no cgroup limit set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := setupV1Root(t, "cpu", "/docker/abc123", map[string]string{
				"cpu.cfs_quota_us":  tt.quota,
				"cpu.cfs_period_us": tt.period,
			})
			cg, err := parseProcCgroup(filepath.Join(root, "proc/self/cgroup"))
			if err != nil {
				t.Fatal(err)
			}

			got, err := cpuQuotaV1(root, cg)
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
				t.Errorf("cpuQuotaV1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMemoryLimitV1(t *testing.T) {
	tests := []struct {
		name    string
		limit   string
		want    int64
		wantErr string
	}{
		{"128 MiB", "134217728\n", 134217728, ""},
		{"unlimited (large value)", "9223372036854771712\n", 0, "no cgroup limit set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := setupV1Root(t, "memory", "/docker/abc123", map[string]string{
				"memory.limit_in_bytes": tt.limit,
			})
			cg, err := parseProcCgroup(filepath.Join(root, "proc/self/cgroup"))
			if err != nil {
				t.Fatal(err)
			}

			got, err := memoryLimitV1(root, cg)
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
				t.Errorf("memoryLimitV1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCPUQuotaWithRootV2(t *testing.T) {
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

func TestMemoryLimitWithRootV2(t *testing.T) {
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

func TestCPUQuotaWithRootV1(t *testing.T) {
	root := setupV1Root(t, "cpu", "/docker/abc123", map[string]string{
		"cpu.cfs_quota_us":  "150000\n",
		"cpu.cfs_period_us": "100000\n",
	})

	got, err := CPUQuotaWithRoot(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.Abs(got-1.5) > 0.001 {
		t.Errorf("CPUQuotaWithRoot() = %v, want 1.5", got)
	}
}

func TestMemoryLimitWithRootV1(t *testing.T) {
	root := setupV1Root(t, "memory", "/docker/abc123", map[string]string{
		"memory.limit_in_bytes": "268435456\n",
	})

	got, err := MemoryLimitWithRoot(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 268435456 {
		t.Errorf("MemoryLimitWithRoot() = %v, want 268435456", got)
	}
}

// testdataExpected holds the expected values from a testdata/*/expected.json.
// Null fields indicate that ErrNoLimit is expected.
type testdataExpected struct {
	CPUQuota    *float64 `json:"cpu_quota"`
	MemoryLimit *int64   `json:"memory_limit"`
}

// TestWithRootFromTestdata runs CPUQuotaWithRoot and MemoryLimitWithRoot
// against filesystem snapshots captured from real Docker containers (or VMs)
// by bin/snapshot-cgroup. Each subdirectory of testdata/ is a separate test
// case containing a proc/ and sys/ tree plus an expected.json.
//
// Regenerate with: bin/gen-cgroupv1-testdata and bin/gen-cgroupv2-testdata
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

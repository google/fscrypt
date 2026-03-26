/*
 * cgroup.go - Read CPU and memory limits from Linux cgroups v2.
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

// Package cgroup reads CPU and memory resource limits from Linux control
// groups (cgroup v2).
//
// References:
//   - cgroups(7):           https://man7.org/linux/man-pages/man7/cgroups.7.html
//   - cgroup v2 (cpu.max, memory.max): https://docs.kernel.org/admin-guide/cgroup-v2.html
//   - /proc/self/cgroup:    https://man7.org/linux/man-pages/man7/cgroups.7.html (see "/proc files")
package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNoLimit indicates that no cgroup limit is set.
var ErrNoLimit = errors.New("no cgroup limit set")

// CPUQuota returns the CPU quota as a fractional number of CPUs (e.g. 0.5
// means half a core). Returns ErrNoLimit if no CPU limit is configured.
func CPUQuota() (float64, error) {
	return CPUQuotaWithRoot("/")
}

// CPUQuotaWithRoot is like CPUQuota but resolves all filesystem paths
// relative to root instead of "/". This is useful for testing with a
// mock filesystem.
func CPUQuotaWithRoot(root string) (float64, error) {
	groupPath, err := parseProcCgroup(filepath.Join(root, "proc/self/cgroup"))
	if err != nil {
		return 0, err
	}
	return cpuQuotaV2(filepath.Join(root, "sys/fs/cgroup", groupPath))
}

// MemoryLimit returns the cgroup memory limit in bytes. Returns ErrNoLimit
// if no memory limit is configured.
func MemoryLimit() (int64, error) {
	return MemoryLimitWithRoot("/")
}

// MemoryLimitWithRoot is like MemoryLimit but resolves all filesystem paths
// relative to root instead of "/". This is useful for testing with a
// mock filesystem.
func MemoryLimitWithRoot(root string) (int64, error) {
	groupPath, err := parseProcCgroup(filepath.Join(root, "proc/self/cgroup"))
	if err != nil {
		return 0, err
	}
	return memoryLimitV2(filepath.Join(root, "sys/fs/cgroup", groupPath))
}

// parseProcCgroup parses /proc/self/cgroup and returns the cgroup v2 group
// path. The v2 entry is the line with hierarchy-ID "0" and an empty
// controller list: "0::<path>".
//
// Returns an error if no v2 entry is found.
//
// https://man7.org/linux/man-pages/man7/cgroups.7.html
func parseProcCgroup(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			return parts[2], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no cgroup v2 entry found in %s", path)
}

// cpuQuotaV2 reads cpu.max from the given cgroup v2 directory.
// Format: "$MAX $PERIOD" or "max $PERIOD".
// https://docs.kernel.org/admin-guide/cgroup-v2.html
func cpuQuotaV2(cgroupDir string) (float64, error) {
	data, err := os.ReadFile(filepath.Join(cgroupDir, "cpu.max"))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNoLimit
		}
		return 0, err
	}
	return parseCPUMax(strings.TrimSpace(string(data)))
}

func parseCPUMax(content string) (float64, error) {
	fields := strings.Fields(content)
	if len(fields) == 0 || len(fields) > 2 {
		return 0, fmt.Errorf("unexpected cpu.max format: %q", content)
	}
	if fields[0] == "max" {
		return 0, ErrNoLimit
	}
	quota, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parsing cpu.max quota: %w", err)
	}
	period := 100000.0
	if len(fields) == 2 {
		period, err = strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return 0, fmt.Errorf("parsing cpu.max period: %w", err)
		}
		if period == 0 {
			return 0, fmt.Errorf("cpu.max period is zero")
		}
	}
	return quota / period, nil
}

// memoryLimitV2 reads memory.max from the given cgroup v2 directory.
func memoryLimitV2(cgroupDir string) (int64, error) {
	data, err := os.ReadFile(filepath.Join(cgroupDir, "memory.max"))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNoLimit
		}
		return 0, err
	}
	return parseMemoryMax(strings.TrimSpace(string(data)))
}

func parseMemoryMax(content string) (int64, error) {
	if content == "max" {
		return 0, ErrNoLimit
	}
	v, err := strconv.ParseInt(content, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing memory.max: %w", err)
	}
	return v, nil
}

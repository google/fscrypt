/*
 * cgroup.go - Read CPU and memory limits from Linux cgroups (v1 and v2).
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
// groups. Both cgroup v1 and v2 are supported.
//
// References:
//   - cgroups(7):           https://man7.org/linux/man-pages/man7/cgroups.7.html
//   - cgroup v2 (cpu.max, memory.max): https://docs.kernel.org/admin-guide/cgroup-v2.html
//   - cgroup v1 CPU bandwidth (cpu.cfs_quota_us, cpu.cfs_period_us):
//     https://docs.kernel.org/scheduler/sched-bwc.html
//   - cgroup v1 memory (memory.limit_in_bytes):
//     https://docs.kernel.org/admin-guide/cgroup-v1/memory.html
//   - /proc/self/cgroup:    https://man7.org/linux/man-pages/man7/cgroups.7.html (see "/proc files")
//   - /proc/self/mountinfo: https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html
package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	cg, err := parseProcCgroup(filepath.Join(root, "proc/self/cgroup"))
	if err != nil {
		return 0, err
	}
	if cg.version == 2 {
		return cpuQuotaV2(filepath.Join(root, "sys/fs/cgroup", cg.v2GroupPath))
	}
	return cpuQuotaV1(root, cg)
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
	cg, err := parseProcCgroup(filepath.Join(root, "proc/self/cgroup"))
	if err != nil {
		return 0, err
	}
	if cg.version == 2 {
		return memoryLimitV2(filepath.Join(root, "sys/fs/cgroup", cg.v2GroupPath))
	}
	return memoryLimitV1(root, cg)
}

// procCgroup holds the parsed contents of /proc/self/cgroup.
//
// The file format is documented in cgroups(7). Each line has the format:
//
//	hierarchy-ID:controller-list:cgroup-path
//
// For v2, there is a single line "0::<path>". For v1, each line has a
// non-zero hierarchy ID and a comma-separated list of controllers.
type procCgroup struct {
	// version is 1 or 2.
	version int
	// v2GroupPath is the cgroup path (only set when version is 2).
	v2GroupPath string
	// v1Subsystems maps controller names to their cgroup paths (only
	// populated when version is 1).
	v1Subsystems map[string]string
}

// parseProcCgroup parses /proc/self/cgroup in a single pass, extracting
// both v2 and v1 information.
// https://man7.org/linux/man-pages/man7/cgroups.7.html
func parseProcCgroup(path string) (procCgroup, error) {
	f, err := os.Open(path)
	if err != nil {
		return procCgroup{}, err
	}
	defer f.Close()

	result := procCgroup{
		version:      1,
		v1Subsystems: make(map[string]string),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		// v2 entry: hierarchy-ID is 0 and controllers field is empty.
		if parts[0] == "0" && parts[1] == "" {
			result.version = 2
			result.v2GroupPath = parts[2]
			continue
		}
		// v1 entry: map each controller to its cgroup path.
		for _, ctrl := range strings.Split(parts[1], ",") {
			if ctrl != "" {
				result.v1Subsystems[ctrl] = parts[2]
			}
		}
	}
	return result, scanner.Err()
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

// cpuQuotaV1 reads cpu.cfs_quota_us and cpu.cfs_period_us from the cpu
// cgroup v1 subsystem.
func cpuQuotaV1(root string, cg procCgroup) (float64, error) {
	cgroupPath, err := v1SubsystemPath(root, "cpu", cg)
	if err != nil {
		return 0, err
	}
	quotaData, err := os.ReadFile(filepath.Join(cgroupPath, "cpu.cfs_quota_us"))
	if err != nil {
		return 0, err
	}
	quota, err := strconv.ParseInt(strings.TrimSpace(string(quotaData)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing cpu.cfs_quota_us: %w", err)
	}
	if quota < 0 {
		return 0, ErrNoLimit
	}
	periodData, err := os.ReadFile(filepath.Join(cgroupPath, "cpu.cfs_period_us"))
	if err != nil {
		return 0, err
	}
	period, err := strconv.ParseInt(strings.TrimSpace(string(periodData)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing cpu.cfs_period_us: %w", err)
	}
	if period == 0 {
		return 0, fmt.Errorf("cpu.cfs_period_us is zero")
	}
	return float64(quota) / float64(period), nil
}

// memoryLimitV1 reads memory.limit_in_bytes from the memory cgroup v1
// subsystem.
func memoryLimitV1(root string, cg procCgroup) (int64, error) {
	cgroupPath, err := v1SubsystemPath(root, "memory", cg)
	if err != nil {
		return 0, err
	}
	data, err := os.ReadFile(filepath.Join(cgroupPath, "memory.limit_in_bytes"))
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing memory.limit_in_bytes: %w", err)
	}
	// The kernel uses a very large value (close to max int64) to indicate
	// "no limit". Treat anything above 1 EiB as unlimited.
	const oneEiB = 1 << 60
	if v >= oneEiB {
		return 0, ErrNoLimit
	}
	return v, nil
}

// v1SubsystemPath finds the filesystem path for a cgroup v1 subsystem by
// looking up the already-parsed /proc/self/cgroup data and correlating it
// with /proc/self/mountinfo. All paths are resolved relative to root.
func v1SubsystemPath(root, subsystem string, cg procCgroup) (string, error) {
	relPath, ok := cg.v1Subsystems[subsystem]
	if !ok {
		return "", fmt.Errorf("cgroup v1 subsystem %q not found", subsystem)
	}
	// mountinfo contains absolute paths (e.g. /sys/fs/cgroup/cpu). We
	// prepend root so that file reads go to the right place.
	procMountInfo := filepath.Join(root, "proc/self/mountinfo")
	mountPoint, mountRoot, err := v1MountPoint(procMountInfo, subsystem)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(mountRoot, relPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, mountPoint, rel), nil
}

// v1MountPoint finds the mount point and root for a cgroup v1 subsystem
// from /proc/self/mountinfo. The returned paths are absolute (as written
// in mountinfo); the caller is responsible for prepending the root.
func v1MountPoint(procMountInfo, subsystem string) (mountPoint, root string, err error) {
	f, err := os.Open(procMountInfo)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		mp, err := parseMountInfoLine(scanner.Text())
		if err != nil {
			continue
		}
		if mp.fsType != "cgroup" {
			continue
		}
		if slices.Contains(mp.superOptions, subsystem) {
			return mp.mountPoint, mp.root, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	return "", "", fmt.Errorf("cgroup v1 mount for %q not found in %s", subsystem, procMountInfo)
}

type mountInfo struct {
	root         string
	mountPoint   string
	fsType       string
	superOptions []string
}

// parseMountInfoLine parses a single line from /proc/self/mountinfo.
// Format: id parent devid root mount opts [optional...] - fstype source superopts
// https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html
func parseMountInfoLine(line string) (mountInfo, error) {
	fields := strings.Split(line, " ")
	if len(fields) < 7 {
		return mountInfo{}, fmt.Errorf("too few fields in mountinfo line")
	}

	root := fields[3]
	mp := fields[4]

	// Find the separator "-" that marks the end of optional fields.
	sepIdx := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sepIdx = i
			break
		}
	}
	if sepIdx == -1 || sepIdx+3 > len(fields) {
		return mountInfo{}, fmt.Errorf("no separator in mountinfo line")
	}

	return mountInfo{
		root:         root,
		mountPoint:   mp,
		fsType:       fields[sepIdx+1],
		superOptions: strings.Split(fields[sepIdx+3], ","),
	}, nil
}

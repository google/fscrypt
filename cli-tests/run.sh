#!/bin/bash
#
# run.sh - run the fscrypt command-line interface tests
#
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#

# Use extra-strict mode.
set -e -u -o pipefail

# Ensure we're in the cli-tests/ directory.
cd "$(dirname "$0")"

# Names of the test devices.
# Variables with these names are exported to the tests.
DEVICES=(DEV DEV_ROOT)

# Names of the mountpoint of each test device.
# Variables with these names are exported to the tests.
MOUNTS=(MNT MNT_ROOT)

# Name of the test user.  This user will be created and deleted by this script.
# This variable is exported to the tests.
TEST_USER=fscrypt-test-user

# The temporary directory to use.
# This variable is exported to the tests.
TMPDIR=$(mktemp -d /tmp/fscrypt.XXXXXX)

# The loopback devices that correspond to each test device.
LOOPS=()

# Update the expected output files to match the actual output?
UPDATE_OUTPUT=false

LONGOPTS_ARRAY=(
'help'
'update-output'
)
LONGOPTS=$(echo "${LONGOPTS_ARRAY[*]}" | tr ' ' ,)

cleanup()
{
	local mnt loop

	# Unmount all the test filesystems.
	for mnt in "${MOUNTS[@]}"; do
		mnt="$TMPDIR/$mnt"
		if mountpoint "$mnt" &> /dev/null; then
			umount "$mnt"
		fi
	done

	# Delete the loopback device of each test device.
	for loop in "${LOOPS[@]}"; do
		losetup -d "$loop"
	done

	# Delete all temporary files.
	rm -rf "${TMPDIR:?}"/*
}

cleanup_full()
{
	cleanup
	rm -rf "$TMPDIR"
	userdel "$TEST_USER" || true
}

# Filters the output of the test script to make the output consistent on every
# run of the test.  For example, references to the mountpoint like
# /tmp/fscrypt.4OTb6y/MNT will be replaced with simply MNT, since the name of
# the temporary directory is different every time.
filter_test_output()
{
	local sedscript=""
	local raw_output=$TMPDIR/raw-test-output
	local i

	cat > "$raw_output"

	# Filter mountpoint and device names.
	for i in "${!DEVICES[@]}"; do
		sedscript+="s@$TMPDIR/${MOUNTS[$i]}@${MOUNTS[$i]}@g;"
		sedscript+="s@${LOOPS[$i]}@${DEVICES[$i]}@g;"
	done

	# Filter the path to fscrypt.conf.
	sedscript+="s@$FSCRYPT_CONF@FSCRYPT_CONF@g;"

	# Filter policy and protector descriptors.
	sedscript+=$(grep -E -o '\<([a-f0-9]{16})|([a-f0-9]{32})\>' \
		     "$raw_output" \
		     | awk '{ printf "s@\\<" $1 "\\>@desc" NR "@g;" }')

	# Filter any other paths in TMPDIR.
	sedscript+="s@$TMPDIR@TMPDIR@g;"

	# At some point, 'bash -c COMMAND' started showing error messages as
	# "bash: line 1: " instead of just "bash: ".  Filter out the "line 1: ".
	sedscript+="s@^bash: line 1: @bash: @;"

	sed -e "$sedscript" "$raw_output"
}

# Prepares to run a test script.
setup_for_test()
{
	local i dev_var mnt_var img mnt loop

	# Start with a clean state.
	cleanup

	# ../bin/fscrypt might not be accessible to $TEST_USER.  Copy it into
	# $TMPDIR so that $TEST_USER is guaranteed to have access to it.
	mkdir "$TMPDIR/bin"
	cp ../bin/fscrypt "$TMPDIR/bin/"
	chmod 755 "$TMPDIR" "$TMPDIR/bin" "$TMPDIR/bin/fscrypt"

	# Create the test filesystems and mountpoints.
	LOOPS=()
	for i in "${!DEVICES[@]}"; do
		dev_var=${DEVICES[$i]}
		mnt_var=${MOUNTS[$i]}
		img="$TMPDIR/$dev_var"
		if ! mkfs.ext4 -O encrypt -F -b 4096 -I 256 "$img" $((1<<15)) \
			&> "$TMPDIR/mkfs.out"
		then
			cat 1>&2 "$TMPDIR/mkfs.out"
			exit 1
		fi
		loop=$(losetup --find --show "$img")
		LOOPS+=("$loop")
		export "$dev_var=$loop"
		mnt="$TMPDIR/$mnt_var"
		export "$mnt_var=$mnt"
		mkdir -p "$mnt"
		mount "$loop" "$mnt"
	done

	# Give the tests their own "root" mount for storing login protectors, so
	# they don't use the real "/".
	export FSCRYPT_ROOT_MNT="$MNT_ROOT"

	# Enable consistent output mode.
	export FSCRYPT_CONSISTENT_OUTPUT="1"

	# Give the tests their own fscrypt.conf.
	export FSCRYPT_CONF="$TMPDIR/fscrypt.conf"
	fscrypt setup --time=1ms --quiet --all-users > /dev/null

	# The tests assume kernel support for v2 policies.
	if ! grep -q '"policy_version": "2"' "$FSCRYPT_CONF"; then
		cat 1>&2 << EOF
ERROR: Can't run these tests because your kernel doesn't support v2 policies.
You need kernel v5.4 or later.
EOF
		exit 1
	fi

	# Set up the test filesystems that aren't already set up.
	fscrypt setup --quiet --all-users "$MNT" > /dev/null
}

run_test()
{
	local t=$1

	# Run the test script.
	set +e
	"./$1.sh" |& filter_test_output > "$t.out.actual"
	status=${PIPESTATUS[0]}
	set -e

	# Check for failure status.
	if [ "$status" != 0 ]; then
		echo 1>&2 "FAILED: $t [exited with failure status $status]"
		if [ -s "$t.out.actual" ]; then
			if (( $(wc -l "$t.out.actual" | cut -f1 -d' ') > 10 )); then
				echo 1>&2 "Last 10 lines of test output:"
				tail -n10 "$t.out.actual" | sed 1>&2 's/^/    /'
				echo 1>&2
				echo 1>&2 "See $t.out.actual for the full output."
			else
				echo 1>&2 "Test output:"
				sed 1>&2 's/^/    /' < "$t.out.actual"
			fi
		fi
		exit 1
	fi

	# Check for output mismatch.
	if ! cmp "$t.out" "$t.out.actual" &> /dev/null; then
		if $UPDATE_OUTPUT; then
			cp "$t.out.actual" "$t.out"
			echo "Updated $t.out"
		else
			echo 1>&2 "FAILED: $t [output mismatch]"
			echo 1>&2 "Differences between $t.out and $t.out.actual:"
			echo 1>&2
			diff 1>&2 "$t.out" "$t.out.actual"
			exit 1
		fi
	fi
	rm -f "$t.out.actual"
}

usage()
{
	cat << EOF
Usage: run.sh [--update-output] [TEST_SCRIPT_NAME]..."
EOF
	exit 1
}

if ! options=$(getopt -o "" -l "$LONGOPTS" -- "$@"); then
	usage
fi
eval set -- "$options"
while (( $# >= 1 )); do
	case "$1" in
	--update-output)
		UPDATE_OUTPUT=true
		;;
	--)
		shift
		break
		;;
	--help|*)
		usage
		;;
	esac
	shift
done

if [ "$(id -u)" != 0 ]; then
	echo 1>&2 "ERROR: You must be root to run these tests."
	exit 1
fi

# Check for prerequisites.
PREREQ_CMDS=(mkfs.ext4 expect keyctl)
PREREQ_PKGS=(e2fsprogs expect keyutils)
for i in ${!PREREQ_CMDS[*]}; do
	if ! type -P "${PREREQ_CMDS[$i]}" > /dev/null; then
		cat 1>&2 << EOF
ERROR: You must install the '${PREREQ_PKGS[$i]}' package to run these tests.
       Try a command like 'sudo apt-get install ${PREREQ_PKGS[$i]}'.
EOF
		exit 1
	fi
done

# Use a consistent umask.
umask 022

# Use a consistent locale, to prevent output mismatches.
export LANG=C
export LC_ALL=C

# Always cleanup fully on exit.
trap cleanup_full EXIT

# Create a test user, so that we can test non-root use of fscrypt.  Give them a
# password, so that we can test creating login passphrase protected directories.
userdel "$TEST_USER" &> /dev/null || true
useradd "$TEST_USER"
echo "$TEST_USER:TEST_USER_PASS" | chpasswd
export TEST_USER

# Let the tests use $TMPDIR if they need it.
export TMPDIR

# Make it so that running 'fscrypt' in the tests runs the correct binary.
export PATH="$TMPDIR/bin:$PATH"

if (( $# >= 1 )); then
	# Tests specified on command line.
	tests=("$@")
else
	# No tests specified on command line.  Just run everything.
	tests=(t_*.sh)
fi
for t in "${tests[@]}"; do
	t=${t%.sh}
	echo "Running $t"
	setup_for_test
	run_test "$t"
done

echo "All tests passed!"

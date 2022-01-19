#!/bin/bash
#
# common.sh - helper functions for fscrypt command-line interface tests
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

# Don't allow running the test scripts directly.  They need to be run via
# run.sh, to set up everything correctly.
if [ -z "${MNT:-}" ] || [ -z "${MNT_ROOT:-}" ]; then
	echo 1>&2 "ERROR: This script can only be run via run.sh, not on its own."
	exit 1
fi

# Prints an error message, then fails the test by exiting with failure status.
_fail()
{
	echo 1>&2 "ERROR: $1"
	exit 1
}

# Runs a shell command and expects that it fails.
_expect_failure()
{
	if eval "$1"; then
		_fail "command unexpectedly succeeded: \"$1\""
	fi
}

# Prints a message to mark the beginning of the next part of the test.
_print_header()
{
	echo
	echo "# $1"
}

# Deletes all files on the test filesystems, including all policies and
# protectors.  Leaves the fscrypt metadata directories themselves.
_reset_filesystems()
{
	local mnt

	for mnt in "$MNT" "$MNT_ROOT"; do
		rm -rf "${mnt:?}"/* "${mnt:?}"/.fscrypt/{policies,protectors}/*
	done
}

# Prints the number of filesystems that have encryption support enabled.
_get_enabled_fs_count()
{
	local count

	count=$(fscrypt status | awk '/filesystems supporting encryption/ { print $4 }')
	if [ -z "$count" ]; then
		_fail "encryption support status line not found"
	fi
	echo "$count"
}

# Gets the descriptor of the given protector.
_get_protector_descriptor()
{
	local mnt=$1
	local source=$2

	case $source in
	custom)
		local name=$3
		local description="custom protector \\\"$name\\\""
		;;
	login)
		local user=$3
		local description="login protector for $user"
		;;
	*)
		_fail "Unknown protector source $source"
	esac

	local descriptor
	descriptor=$(fscrypt status "$mnt" |
		     awk -F '   *' '{ if ($3 == "'"$description"'") print $1 }')
	if [ -z "$descriptor" ]; then
		_fail "Can't find $description on $mnt"
	fi
	echo "$descriptor"
}

# Gets the descriptor of the login protector for $TEST_USER.
_get_login_descriptor()
{
	_get_protector_descriptor "$MNT_ROOT" login "$TEST_USER"
}

# Prints the number of filesystems that have fscrypt metadata.
_get_setup_fs_count()
{
	local count

	count=$(fscrypt status | awk '/filesystems with fscrypt metadata/ { print $5 }')
	if [ -z "$count" ]; then
		_fail "fscrypt metadata status line not found"
	fi
	echo "$count"
}

# Removes all fscrypt metadata from the given filesystem.
_rm_metadata()
{
	rm -r "${1:?}/.fscrypt"
}

# Runs a shell command, ignoring its output (stdout and stderr) if it succeeds.
# If the command fails, prints its output and fails the test.
_run_noisy_command()
{
	if ! eval "$1" &> "$TMPDIR/out"; then
		_fail "Command failed: '$1'.  Output was: $(cat "$TMPDIR/out")"
	fi
}

# Runs the given shell command as the test user.
_user_do()
{
	su "$TEST_USER" --shell=/bin/bash --command="export PATH='$PATH'; $1"
}

# Runs the given shell command as the test user and expects it to fail.
_user_do_and_expect_failure()
{
	_expect_failure "_user_do '$1'"
}

# Clear the test user's user keyring and unlink it from root's user keyring, if
# it is linked into it.
_cleanup_user_keyrings()
{
	local ringid

	ringid=$(_user_do "keyctl show @u" | awk '/keyring: _uid/{print $1}')

	_user_do "keyctl clear $ringid"
	keyctl unlink "$ringid" @u &> /dev/null || true
}

# Gives the test a new session keyring which contains the test user's keyring
# but not root's keyring.  Also clears the test user's keyring.  This must be
# called at the beginning of the test script as it may re-execute the script.
_setup_session_keyring()
{
	# This *should* just use 'keyctl new_session', but that doesn't work if
	# the session keyring is owned by a user other than root.  So instead we
	# have to use 'keyctl session' and re-execute the script.
	if [ -z "${FSCRYPT_SESSION_KEYRING_SET:-}" ]; then
		export FSCRYPT_SESSION_KEYRING_SET=1
		set +e
		keyctl session - "$0" |& grep -v '^Joined session keyring'
		exit "${PIPESTATUS[0]}"
	fi

	# Link the test user's keyring into the new session keyring.
	keyctl setperm @s 0x3f000000 # all possessor permissions
	_user_do "keyctl link @u @s"

	# Clear the test user's keyring.
	_user_do "keyctl clear @u"
}

# Wraps the 'expect' command to force subprocesses to have 80-column output.
expect()
{
	command expect -c 'set stty_init "cols 80"' -f -
}

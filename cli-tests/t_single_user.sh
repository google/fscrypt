#!/bin/bash

# Test 'fscrypt setup' without --all-users.

cd "$(dirname "$0")"
. common.sh

_rm_metadata "$MNT_ROOT"
_rm_metadata "$MNT"
rm "$FSCRYPT_CONF"
fscrypt setup --time=1ms --quiet
fscrypt setup --time=1ms --quiet "$MNT"
fscrypt status "$MNT"
_user_do "fscrypt status \"$MNT\""

dir=$MNT/dir

begin()
{
	_reset_filesystems
	mkdir "$dir"
	_print_header "$1"
}

begin "Encrypt, lock, and unlock as root"
echo hunter2 | fscrypt encrypt --quiet --name=dir --skip-unlock "$dir"
echo hunter2 | fscrypt unlock --quiet "$dir"
fscrypt lock "$dir"

begin "Encrypt as root with user's login protector"
echo TEST_USER_PASS | fscrypt encrypt --quiet --source=pam_passphrase --user="$TEST_USER" "$dir"
# The user should be able to update the policy and protectors created by the
# above command themselves.  The easiest way to test this is by updating the
# policy to remove the auto-generated recovery protector.  This verifies that
# (a) the policy was made owned by the user, and that (b) policy updates fall
# back to overwrites when the process cannot write to the containing directory.
# (It would be better to test updating the protectors too, but this is the
# easiest test to do here.)
policy=$(fscrypt status "$dir" | awk '/Policy/{print $2}')
recovery_protector=$(_get_protector_descriptor "$MNT" custom 'Recovery passphrase for dir')
_user_do "fscrypt metadata remove-protector-from-policy --force --protector=$MNT:$recovery_protector --policy=$MNT:$policy"
chown "$TEST_USER" "$dir"
_user_do "fscrypt lock $dir"
_user_do "echo TEST_USER_PASS | fscrypt unlock $dir"

begin "Encrypt as user (should fail)"
chown "$TEST_USER" "$dir"
_user_do_and_expect_failure "echo hunter2 | fscrypt encrypt --quiet --name=dir --skip-unlock \"$dir\""

begin "Encrypt as user if they set up filesystem (should succeed)"
_rm_metadata "$MNT"
chown "$TEST_USER" "$MNT"
chown "$TEST_USER" "$dir"
_user_do "fscrypt setup --time=1ms --quiet $MNT"
_user_do "echo hunter2 | fscrypt encrypt --quiet --name=dir3 --skip-unlock \"$dir\""

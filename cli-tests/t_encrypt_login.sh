#!/bin/bash

# Test encrypting a directory using a login (pam_passphrase) protector.

cd "$(dirname "$0")"
. common.sh

dir="$MNT/dir"

begin()
{
	_reset_filesystems
	mkdir "$dir"
	_print_header "$1"
}

show_status()
{
	local encrypted=$1

	fscrypt status "$MNT"
	fscrypt status "$MNT_ROOT"
	if $encrypted; then
		fscrypt status "$dir"
	else
		_expect_failure "fscrypt status '$dir'"
	fi
}

get_login_protector()
{
	fscrypt status "$dir" | awk '/login protector/{print $1}'
}

begin "Encrypt with login protector"
chown "$TEST_USER" "$dir"
_user_do "echo TEST_USER_PASS | fscrypt encrypt --quiet --source=pam_passphrase '$dir'"
show_status true
recovery_passphrase=$(grep -E '^ +[a-z]{20}$' "$dir/fscrypt_recovery_readme.txt" | sed 's/^ +//')
recovery_protector=$(fscrypt status "$dir" | awk '/Recovery passphrase/{print $1}')
login_protector=$(get_login_protector)
_print_header "=> Lock, then unlock with login passphrase"
_user_do "fscrypt lock '$dir'"
# FIXME: should we be able to use $MNT:$login_protector here?
_user_do "echo TEST_USER_PASS | fscrypt unlock --quiet --unlock-with=$MNT_ROOT:$login_protector '$dir'"
_print_header "=> Lock, then unlock with recovery passphrase"
_user_do "fscrypt lock '$dir'"
_user_do "echo $recovery_passphrase | fscrypt unlock --quiet --unlock-with=$MNT:$recovery_protector '$dir'"

begin "Encrypt with login protector, interactively"
chown "$TEST_USER" "$dir"
_user_do expect << EOF
spawn fscrypt encrypt "$dir"
expect "Enter the source number for the new protector"
send "1\r"
expect "Enter login passphrase"
send "TEST_USER_PASS\r"
expect eof
EOF
show_status true

begin "Encrypt with login protector as root"
echo TEST_USER_PASS | fscrypt encrypt --quiet --source=pam_passphrase --user="$TEST_USER" "$dir"
show_status true
# The newly-created login protector should be owned by the user, not root.
login_protector=$(get_login_protector)
owner=$(stat -c "%U:%G" "$MNT_ROOT/.fscrypt/protectors/$login_protector")
echo -e "\nProtector is owned by $owner"

begin "Encrypt with login protector with --no-recovery"
chown "$TEST_USER" "$dir"
_user_do "echo TEST_USER_PASS | fscrypt encrypt --quiet --source=pam_passphrase --no-recovery '$dir'"
show_status true

begin "Encrypt with login protector on root fs (shouldn't generate a recovery passphrase)"
mkdir "$MNT_ROOT/dir"
chown "$TEST_USER" "$MNT_ROOT/dir"
_user_do "echo TEST_USER_PASS | fscrypt encrypt --quiet --source=pam_passphrase --no-recovery '$MNT_ROOT/dir'"
fscrypt status "$MNT_ROOT/dir"
fscrypt status "$MNT_ROOT"
rmdir "$MNT_ROOT/dir"

begin "Try to give a login protector a name"
chown "$TEST_USER" "$dir"
_user_do_and_expect_failure \
	"echo TEST_USER_PASS | fscrypt encrypt --quiet --source=pam_passphrase --name=prot '$dir'"
show_status false

begin "Try to use the wrong login passphrase"
chown "$TEST_USER" "$dir"
_user_do_and_expect_failure \
	"echo wrong_passphrase | fscrypt encrypt --quiet --source=pam_passphrase '$dir'"
show_status false

begin "Test that linked protector works even if UUID link is broken"
echo TEST_USER_PASS | fscrypt encrypt --quiet --source=pam_passphrase --user="$TEST_USER" "$dir"
protector=$(get_login_protector)
link_file=$MNT/.fscrypt/protectors/$protector.link
[ -e "$link_file" ] || _fail "$link_file does not exist"
sed -i 's/UUID=.*/UUID=00000000-0000-0000-0000-000000000000/' "$link_file"
fscrypt status "$MNT"

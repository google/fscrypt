#!/bin/bash

# General tests for 'fscrypt encrypt'.  For protector-specific tests, see
# t_encrypt_custom, t_encrypt_login, and t_encrypt_raw_key.

cd "$(dirname "$0")"
. common.sh

dir="$MNT/dir"

begin()
{
	_reset_filesystems
	mkdir "$dir"
	_print_header "$@"
}

show_status()
{
	local encrypted=$1

	fscrypt status "$MNT"
	if $encrypted; then
		fscrypt status "$dir"
	else
		_expect_failure "fscrypt status '$dir'"
	fi
}

begin "Try to encrypt a nonexistent directory"
_expect_failure "echo hunter2 | fscrypt encrypt --quiet '$MNT/nonexistent'"
show_status false

begin "Try to encrypt a nonempty directory"
touch "$dir/file"
_expect_failure "echo hunter2 | fscrypt encrypt --quiet '$dir'"
show_status false
_print_header "=> with trailing slash"
_expect_failure "echo hunter2 | fscrypt encrypt --quiet '$dir/'"
show_status false

begin "Encrypt a directory as non-root user"
chown "$TEST_USER" "$dir"
_user_do "echo hunter2 | fscrypt encrypt --quiet --name=prot '$dir'"
show_status true
_user_do "fscrypt status '$MNT'"
_user_do "fscrypt status '$dir'"

_print_header "Try to encrypt an already-encrypted directory"
_user_do_and_expect_failure "echo hunter2 | fscrypt encrypt --quiet --name=prot '$dir'"

begin "Try to encrypt another user's directory as a non-root user"
_user_do_and_expect_failure "echo hunter2 | fscrypt encrypt --quiet --name=prot '$dir'"
show_status false

#!/bin/bash

# Test encrypting a directory using a custom_passphrase protector.

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
	if $encrypted; then
		fscrypt status "$dir"
	else
		_expect_failure "fscrypt status '$dir'"
	fi
}

begin "Encrypt with custom passphrase protector"
echo hunter2 | fscrypt encrypt --quiet --name=prot "$dir"
show_status true

begin "Encrypt with custom passphrase protector, interactively"
expect << EOF
spawn fscrypt encrypt "$dir"
expect "Enter the source number for the new protector"
send "2\r"
expect "Enter a name for the new protector:"
send "prot\r"
expect "Enter custom passphrase"
send "hunter2\r"
expect "Confirm passphrase"
send "hunter2\r"
expect eof
EOF
show_status true

begin "Try to use a custom protector without a name"
_expect_failure "echo hunter2 | fscrypt encrypt --quiet '$dir'"
show_status false

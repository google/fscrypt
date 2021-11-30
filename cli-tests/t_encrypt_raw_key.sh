#!/bin/bash

# Test encrypting a directory using a raw_key protector.

cd "$(dirname "$0")"
. common.sh

dir="$MNT/dir"
raw_key_file="$TMPDIR/raw_key"

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

begin "Encrypt with raw_key protector from file"
head -c 32 /dev/urandom > "$raw_key_file"
fscrypt encrypt --quiet --name=prot --source=raw_key --key="$raw_key_file" "$dir"
show_status true

begin "Encrypt with raw_key protector from stdin"
head -c 32 /dev/urandom | fscrypt encrypt --quiet --name=prot --source=raw_key "$dir"
show_status true

begin "Try to encrypt with raw_key protector from file, using wrong key length"
head -c 16 /dev/urandom > "$raw_key_file"
_expect_failure "fscrypt encrypt --quiet --name=prot --source=raw_key --key='$raw_key_file' '$dir'"
show_status false

begin "Try to encrypt with raw_key protector from stdin, using wrong key length"
_expect_failure "head -c 16 /dev/urandom | fscrypt encrypt --quiet --name=prot --source=raw_key '$dir'"
show_status false

begin "Encrypt with raw_key protector from file, unlock from stdin"
head -c 32 /dev/urandom > "$raw_key_file"
fscrypt encrypt --quiet --name=prot --source=raw_key --key="$raw_key_file" "$dir"
fscrypt lock "$dir"
fscrypt unlock --quiet "$dir" < "$raw_key_file"
show_status true

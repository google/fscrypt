#!/bin/bash

# Test unlocking a directory.

cd "$(dirname "$0")"
. common.sh

dir="$MNT/dir"
mkdir "$dir"

_print_header "Encrypt directory with --skip-unlock"
echo hunter2 | fscrypt encrypt --quiet --name=prot --skip-unlock "$dir"
_print_header "=> Check dir status"
fscrypt status "$dir"
_expect_failure "touch '$dir/file'"
policy=$(fscrypt status "$dir" | awk '/Policy:/{print $2}')
_print_header "=> Get policy status via mount:"
fscrypt status "$MNT" | grep "^$policy"

_print_header "Unlock directory"
echo hunter2 | fscrypt unlock "$dir"
_print_header "=> Check dir status"
fscrypt status "$dir"
echo contents > "$dir/file"
_print_header "=> Get policy status via mount:"
fscrypt status "$MNT" | grep "^$policy"

_print_header "Lock by cycling mount"
umount "$MNT"
mount "$DEV" "$MNT"
_print_header "=> Check dir status"
fscrypt status "$dir"
_expect_failure "mkdir '$dir/subdir'"
_print_header "=> Get policy status via mount:"
fscrypt status "$MNT" | grep "^$policy"

_print_header "Try to unlock with wrong passphrase"
_expect_failure "echo bad | fscrypt unlock --quiet '$dir'"
fscrypt status "$dir"

_print_header "Unlock directory"
echo hunter2 | fscrypt unlock "$dir"
_print_header "=> Check dir status"
fscrypt status "$dir"
cat "$dir/file"
_print_header "=> Get policy status via mount:"
fscrypt status "$MNT" | grep "^$policy"

_print_header "Try to unlock with corrupt policy metadata"
umount "$MNT"
mount "$DEV" "$MNT"
echo bad > "$MNT/.fscrypt/policies/$policy"
_expect_failure "echo hunter2 | fscrypt unlock '$dir'"

_reset_filesystems

_print_header "Try to unlock with missing policy metadata"
mkdir "$dir"
echo hunter2 | fscrypt encrypt --quiet --name=prot --skip-unlock "$dir"
rm "$MNT"/.fscrypt/policies/*
_expect_failure "echo hunter2 | fscrypt unlock '$dir'"

_reset_filesystems

_print_header "Try to unlock with missing protector metadata"
mkdir "$dir"
echo hunter2 | fscrypt encrypt --quiet --name=prot --skip-unlock "$dir"
rm "$MNT"/.fscrypt/protectors/*
_expect_failure "echo hunter2 | fscrypt unlock '$dir'"

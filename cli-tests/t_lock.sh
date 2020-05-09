#!/bin/bash

# Test locking a directory.

cd "$(dirname "$0")"
. common.sh

dir="$MNT/dir"
mkdir "$dir"

_print_header "Encrypt directory"
echo hunter2 | fscrypt encrypt --quiet --name=prot "$dir"
fscrypt status "$dir"
echo contents > "$dir/file"

_print_header "Lock directory"
fscrypt lock "$dir"
_print_header "=> filenames should be in encrypted form"
_expect_failure "cat '$dir/file'"
_print_header "=> shouldn't be able to create a subdirectory"
_expect_failure "mkdir '$dir/subdir'"

_print_header "Unlock directory"
echo hunter2 | fscrypt unlock "$dir"
fscrypt status "$dir"
cat "$dir/file"

_print_header "Try to lock directory while files busy"
exec 3<"$dir/file"
_expect_failure "fscrypt lock '$dir'"
_print_header "=> status should be incompletely locked"
fscrypt status "$dir"
_print_header "=> open file should still be readable"
cat "$dir/file"
_print_header "=> shouldn't be able to create a new file"
_expect_failure "bash -c \"echo contents > '$dir/file2'\""

_print_header "Finish locking directory"
exec 3<&-
fscrypt lock "$dir"
fscrypt status "$dir"
_expect_failure "cat '$dir/file'"
_expect_failure "mkdir '$dir/subdir'"

_print_header "Try to lock directory while other user has unlocked"
chown "$TEST_USER" "$dir"
_user_do "echo hunter2 | fscrypt unlock '$dir'"
_expect_failure "fscrypt lock '$dir'"
cat "$dir/file"
fscrypt lock --all-users "$dir"
_expect_failure "cat '$dir/file'"

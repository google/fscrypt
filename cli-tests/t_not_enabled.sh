#!/bin/bash

# Test that fscrypt fails when the filesystem doesn't have the encrypt feature
# enabled.  Then test enabling it.

cd "$(dirname "$0")"
. common.sh

dir="$MNT/dir"
mkdir "$dir"

_print_header "Disable encryption on $DEV"
count_before=$(_get_enabled_fs_count)
umount "$MNT"
_run_noisy_command "debugfs -w -R 'feature -encrypt' '$DEV'"
mount "$DEV" "$MNT"
count_after=$(_get_enabled_fs_count)
(( count_after == count_before - 1 )) || _fail "wrong enabled count"

_print_header "Try to encrypt a directory when encryption is disabled"
_expect_failure "fscrypt encrypt '$dir'"

_print_header "Try to unlock a directory when encryption is disabled"
_expect_failure "fscrypt unlock '$dir'"

_print_header "Try to lock a directory when encryption is disabled"
_expect_failure "fscrypt lock '$dir'"

_print_header "Enable encryption on $DEV"
_run_noisy_command "tune2fs -O encrypt '$DEV'"

_print_header "Encrypt a directory when encryption was just enabled"
echo hunter2 | fscrypt encrypt --quiet --source=custom_passphrase --name=prot "$dir"
fscrypt status "$dir"

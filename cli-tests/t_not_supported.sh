#!/bin/bash

# Test that fscrypt fails when the filesystem doesn't support encryption.

cd "$(dirname "$0")"
. common.sh

_print_header "Mount tmpfs"
umount "$MNT"
mount tmpfs -t tmpfs -o size=128m "$MNT"

_print_header "Try to create fscrypt metadata on tmpfs"
_expect_failure "fscrypt setup --quiet '$MNT'"

_print_header "Try to encrypt a directory on tmpfs"
mkdir "$MNT/dir"
_expect_failure "fscrypt encrypt '$MNT/dir'"

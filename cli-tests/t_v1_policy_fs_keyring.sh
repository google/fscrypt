#!/bin/bash

# Test using v1 encryption policies (deprecated) with
# use_fs_keyring_for_v1_policies = true.

# This works similar to v2 policies, except locking and unlocking (including
# 'fscrypt encrypt' without --skip-unlock) will only work as root.

cd "$(dirname "$0")"
. common.sh

_print_header "Enable v1 policies with fs keyring"
sed -E -e 's/"use_fs_keyring_for_v1_policies": +false/"use_fs_keyring_for_v1_policies": true/' \
    -e 's/"policy_version": +"2"/"policy_version": "1"/' \
    -i "$FSCRYPT_CONF"

dir="$MNT/dir"
mkdir "$dir"
chown "$TEST_USER" "$dir"

_print_header "Try to encrypt directory as user"
_user_do_and_expect_failure "echo hunter2 | fscrypt encrypt --quiet --name=prot '$dir'"
_expect_failure "fscrypt status '$dir'"

_print_header "Encrypt directory as user with --skip-unlock"
_user_do "echo hunter2 | fscrypt encrypt --quiet --name=prot --skip-unlock '$dir'"
fscrypt status "$dir"
_expect_failure "mkdir '$dir/subdir'"

_print_header "Try to unlock directory as user"
_user_do_and_expect_failure "echo hunter2 | fscrypt unlock '$dir'"

_print_header "Unlock directory as root"
echo hunter2 | fscrypt unlock "$dir"
mkdir "$dir/subdir"
echo contents > "$dir/file"
fscrypt status "$dir"

_print_header "Try to lock directory as user"
_user_do_and_expect_failure "fscrypt lock '$dir'"

_print_header "Lock directory as root"
fscrypt lock "$dir"
_expect_failure "cat '$dir/file'"
fscrypt status "$dir"

_print_header "Check that user can access file when directory is unlocked by root"
echo hunter2 | fscrypt unlock "$dir"
_user_do "cat '$dir/file'"

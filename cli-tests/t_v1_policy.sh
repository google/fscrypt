#!/bin/bash

# Test using v1 encryption policies (deprecated).

cd "$(dirname "$0")"
. common.sh

_setup_session_keyring
trap _cleanup_user_keyrings EXIT

dir="$MNT/dir"
mkdir "$dir"
chown "$TEST_USER" "$dir"

_print_header "Set policy_version 1"
sed -i 's/"policy_version": "2"/"policy_version": "1"/' "$FSCRYPT_CONF"

_print_header "Try to encrypt as root"
_expect_failure "echo hunter2 | fscrypt encrypt --quiet --name=prot '$dir'"

_print_header "Try to use --user=root as user"
_user_do_and_expect_failure "echo hunter2 | fscrypt encrypt --quiet --name=prot --user=root '$dir'"

_print_header "Try to encrypt without user keyring in session keyring"
_user_do "keyctl unlink @u @s"
_user_do_and_expect_failure "echo hunter2 | fscrypt encrypt --quiet --name=prot '$dir'"
_user_do "keyctl link @u @s"

_print_header "Encrypt a directory"
_user_do "echo hunter2 | fscrypt encrypt --quiet --name=prot '$dir'"

_print_header "Get dir status as user"
_user_do "fscrypt status '$dir'"

_print_header "Get dir status as root"
fscrypt status "$dir"

_print_header "Create files in v1-encrypted directory"
echo contents > "$dir/file"
mkdir "$dir/subdir"
ln -s target "$dir/symlink"

# Due to the limitations of the v1 key management mechanism, 'fscrypt lock' only
# works when run as root and with the --user argument.

_print_header "Try to lock v1-encrypted directory as user"
_user_do_and_expect_failure "fscrypt lock '$dir'"
_user_do "fscrypt status '$dir'"

_print_header "Try to lock v1-encrypted directory as root without --user"
_expect_failure "fscrypt lock '$dir'"
_user_do "fscrypt status '$dir'"

_print_header "Lock v1-encrypted directory"
fscrypt lock "$dir" --user="$TEST_USER"
_user_do "fscrypt status '$dir'"
_expect_failure "cat '$dir/file'"

# 'fscrypt lock' and 'fscrypt status' implement a heuristic that should detect
# the "files busy" case with v1.
_print_header "Testing incompletely locking v1-encrypted directory"
_user_do "echo hunter2 | fscrypt unlock '$dir'"
exec 3<"$dir/file"
_expect_failure "fscrypt lock '$dir' --user='$TEST_USER'"
_user_do "fscrypt status '$dir'"
# ... except in this case, because we can't detect it without a directory path.
_user_do "fscrypt status '$MNT'"
exec 3<&-
_print_header "Finishing locking v1-encrypted directory"
fscrypt lock "$dir" --user="$TEST_USER"
_user_do "fscrypt status '$dir'"
_expect_failure "cat '$dir/file'"

#!/bin/bash

# Test changing the passphrase of a custom_passphrase protector.

cd "$(dirname "$0")"
. common.sh

dir="$MNT/dir"

_print_header "Create encrypted directory"
mkdir "$dir"
echo pass1 | fscrypt encrypt --quiet --name=prot --skip-unlock "$dir"

_print_header "Try to unlock with wrong passphrase"
_expect_failure "echo pass2 | fscrypt unlock --quiet '$dir'"
_expect_failure "mkdir '$dir/subdir'"
protector=$(fscrypt status "$dir" | awk '/custom protector/{print $1}')

_print_header "Change passphrase"
echo $'pass1\npass2' | \
	fscrypt metadata change-passphrase --protector="$MNT:$protector" --quiet

_print_header "Try to unlock with old passphrase"
_expect_failure "echo pass1 | fscrypt unlock --quiet '$dir'"
_expect_failure "mkdir '$dir/subdir'"

_print_header "Unlock with new passphrase"
echo pass2 | fscrypt unlock --quiet "$dir"
mkdir "$dir/subdir"
rmdir "$dir/subdir"

_print_header "Try to change passphrase (interactively, mismatch)"
expect << EOF
spawn fscrypt metadata change-passphrase --protector=$MNT:$protector
expect "Enter old custom passphrase"
send "pass2\r"
expect "Enter new custom passphrase"
send "pass3\r"
expect "Confirm passphrase"
send "bad\r"
expect eof
EOF

_print_header "Change passphrase (interactively)"
expect << EOF
spawn fscrypt metadata change-passphrase --protector=$MNT:$protector
expect "Enter old custom passphrase"
send "pass2\r"
expect "Enter new custom passphrase"
send "pass3\r"
expect "Confirm passphrase"
send "pass3\r"
expect eof
EOF

_print_header "Lock, then unlock with new passphrase"
fscrypt lock "$dir"
_expect_failure "mkdir '$dir/subdir'"
echo pass3 | fscrypt unlock --quiet "$dir"
mkdir "$dir/subdir"

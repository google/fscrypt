#!/bin/bash

# Test getting global, filesystem, and unencrypted directory status
# when the filesystem is or isn't set up for fscrypt.

cd "$(dirname "$0")"
. common.sh

dir="$MNT/dir"
mkdir "$dir"

filter_mnt_status()
{
	awk '$1 == "'"$MNT"'" { print $3, $4, $5 }'
}

# Initially, $MNT has encryption enabled and fscrypt setup.

enabled_count1=$(_get_enabled_fs_count)
setup_count1=$(_get_setup_fs_count)


_print_header "Get status of setup mountpoint via global status"
fscrypt status | filter_mnt_status
_user_do "fscrypt status" | filter_mnt_status

_print_header "Get status of setup mountpoint"
fscrypt status "$MNT"
_user_do "fscrypt status '$MNT'"

_print_header "Get status of unencrypted directory on setup mountpoint"
_expect_failure "fscrypt status '$dir'"
_user_do_and_expect_failure "fscrypt status '$dir'"

_print_header "Remove fscrypt metadata from $MNT"
_rm_metadata "$MNT"

# Now, $MNT has encryption enabled but fscrypt *not* setup.

_print_header "Check enabled / setup count again"
enabled_count2=$(_get_enabled_fs_count)
setup_count2=$(_get_setup_fs_count)
(( enabled_count2 == enabled_count1 )) || _fail "wrong enabled count"
(( setup_count2 == setup_count1 - 1 )) || _fail "wrong setup count"

_print_header "Get status of not-setup mounntpoint via global status"
fscrypt status | filter_mnt_status
_user_do "fscrypt status" | filter_mnt_status

_print_header "Get status of not-setup mountpoint"
_expect_failure "fscrypt status '$MNT'"
_user_do_and_expect_failure "fscrypt status '$MNT'"

_print_header "Get status of unencrypted directory on not-setup mountpoint"
_expect_failure "fscrypt status '$dir'"
_user_do_and_expect_failure "fscrypt status '$dir'"

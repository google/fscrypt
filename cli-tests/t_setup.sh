#!/bin/bash

# Test 'fscrypt setup'.

cd "$(dirname "$0")"
. common.sh

# global setup

_print_header "fscrypt setup creates fscrypt.conf"
rm -f "$FSCRYPT_CONF"
fscrypt setup --time=1ms

_print_header "fscrypt setup creates fscrypt.conf and /.fscrypt"
_rm_metadata "$MNT_ROOT"
rm -f "$FSCRYPT_CONF"
echo y | fscrypt setup --time=1ms
[ -e "$MNT_ROOT/.fscrypt" ]

_print_header "fscrypt setup when fscrypt.conf already exists (cancel)"
_expect_failure "echo | fscrypt setup --time=1ms"

_print_header "fscrypt setup when fscrypt.conf already exists (cancel 2)"
_expect_failure "echo N | fscrypt setup --time=1ms"

_print_header "fscrypt setup when fscrypt.conf already exists (accept)"
echo y | fscrypt setup --time=1ms

_print_header "fscrypt setup --quiet when fscrypt.conf already exists"
_expect_failure "fscrypt setup --quiet --time=1ms"

_print_header "fscrypt setup --quiet --force when fscrypt.conf already exists"
fscrypt setup --quiet --force --time=1ms


# filesystem setup

_print_header "fscrypt setup filesystem"
_rm_metadata "$MNT"
echo y | fscrypt setup "$MNT"
[ -e "$MNT/.fscrypt" ]

_print_header "fscrypt setup filesystem (already set up)"
_expect_failure "fscrypt setup '$MNT'"

_print_header "no config file"
rm -f "$FSCRYPT_CONF"
_expect_failure "fscrypt setup '$MNT'"

_print_header "bad config file"
echo bad > "$FSCRYPT_CONF"
_expect_failure "fscrypt setup '$MNT'"

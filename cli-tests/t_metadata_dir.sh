#!/bin/bash

# Test metadata_dir config option.

cd "$(dirname "$0")"
. common.sh

# filesystem setup

mddir=$MNT_ROOT/fscrypt_metadata
mkdir "$mddir"
sed -e "s+\"metadata_dir\": \"\"+\"metadata_dir\": \"$mddir\"+" \
    -i "$FSCRYPT_CONF"

dir="$MNT/dir"
mkdir "$dir"

_print_header "fscrypt setup filesystem"
_rm_metadata "$MNT"
fscrypt setup "$MNT"
[ ! -e "$MNT/.fscrypt" ]
[ -e "$mddir/.fscrypt" ]

_print_header "fscrypt encrypt directory"
echo hunter2 | fscrypt encrypt --quiet --source=custom_passphrase --name=prot "$dir"
ls "$mddir"/.fscrypt
[ -n "$(find "$mddir"/.fscrypt/policies -type f)" ]
[ -n "$(find "$mddir"/.fscrypt/protectors -type f)" ]
fscrypt status "$dir"
echo contents > "$dir"/file

_print_header "Lock directory"
fscrypt lock "$dir"

rm -rf "$mddir"

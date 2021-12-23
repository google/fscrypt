#!/bin/bash

# Test 'fscrypt metadata'.

cd "$(dirname "$0")"
. common.sh

# Create three protectors, and a policy protected by them.
echo foo | fscrypt metadata create protector "$MNT" \
	--quiet --name=foo --source=custom_passphrase
echo bar | fscrypt metadata create protector "$MNT" \
	--quiet --name=bar --source=custom_passphrase
echo baz | fscrypt metadata create protector "$MNT" \
	--quiet --name=baz --source=custom_passphrase
prot_foo=$MNT:$(_get_protector_descriptor "$MNT" custom foo)
prot_bar=$MNT:$(_get_protector_descriptor "$MNT" custom bar)
desc_baz=$(_get_protector_descriptor "$MNT" custom baz)
prot_baz=$MNT:$desc_baz
echo foo | fscrypt metadata create policy "$MNT" --quiet \
	--protector="$prot_foo"
policy=$MNT:$(fscrypt status "$MNT" | grep -A10 "^POLICY" | \
	      tail -1 | awk '{print $1}')
echo -e "bar\nfoo" | fscrypt metadata add-protector-to-policy --quiet \
	--policy="$policy" --protector="$prot_bar"
echo -e "baz\nfoo" | fscrypt metadata add-protector-to-policy --quiet \
	--policy="$policy" --protector="$prot_baz" --unlock-with="$prot_foo"
fscrypt status "$MNT"

# Remove two of the protectors from the policy.
# Make sure that this works even if the protector was already deleted.
fscrypt metadata remove-protector-from-policy --quiet --force \
	--policy="$policy" --protector="$prot_bar"
rm "$MNT/.fscrypt/protectors/$desc_baz"
fscrypt metadata remove-protector-from-policy --quiet --force \
	--policy="$policy" --protector="$prot_baz"
fscrypt status "$MNT"

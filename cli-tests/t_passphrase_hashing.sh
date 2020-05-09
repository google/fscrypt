#!/bin/bash

# Test that the passphrase hashing seems to take long enough.

cd "$(dirname "$0")"
. common.sh

dir="$MNT/dir"

# Test encrypting 5 dirs with default of 1s.
fscrypt setup --force --quiet
start_time=$(date +%s)
for i in $(seq 5); do
	rm -rf "$dir"
	mkdir "$dir"
	echo hunter2 | fscrypt encrypt --quiet --name="prot$i" "$dir"
done
end_time=$(date +%s)
elapsed=$((end_time - start_time))
if (( elapsed <= 3 )); then
	_fail "Passphrase hashing was much faster than expected! (expected about 5 x 1 == 5s, got ${elapsed}s)"
fi

# Test encrypting 1 dir with difficulty overridden to 5s.
fscrypt setup --force --quiet --time=5s
start_time=$(date +%s)
rm -rf "$dir"
mkdir "$dir"
echo hunter2 | fscrypt encrypt --quiet --name=prot6 "$dir"
end_time=$(date +%s)
elapsed=$((end_time - start_time))
if (( elapsed <= 3 )); then
	_fail "Passphrase hashing was much faster than expected! (expected about 5s, got ${elapsed}s)"
fi

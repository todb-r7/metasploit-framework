#!/bin/sh

# COMMITER_KEYS_URL='https://raw.githubusercontent.com/wiki/rapid7/metasploit-framework/Committer-Keys.md'
COMMITTER_KEYS_URL='https://gist.githubusercontent.com/todb-r7/38869e2dad97b64cc00a/raw/9064e015fc5326c79369823bb9860c8a95c1d6d8/k.md'
KEY_URLS=$(
 \curl -sSL $COMMITTER_KEYS_URL |
 \awk '$4 ~/https:\/\/keybase.io\//' |
 \sed 's#.*\(https://keybase.io/[^)]*\).*#\1/key.asc#'
)
for key in $KEY_URLS; do
  echo Importing $key...
  \curl -sSL $key | gpg --quiet --import -
done


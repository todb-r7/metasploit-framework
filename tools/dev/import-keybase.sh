#!/bin/sh

COMMITTER_KEYS_URL='https://raw.githubusercontent.com/wiki/rapid7/metasploit-framework/Committer-Keys.md'
KEY_URLS=$(
 \curl -sSL $COMMITTER_KEYS_URL |
 \awk '$4 ~/https:\/\/keybase.io\//' |
 \sed 's#.*\(https://keybase.io/[^)]*\).*#\1/key.asc#'
)
for key in $KEY_URLS; do
  echo Importing $key...
  \curl -sSL $key | gpg --quiet --import -
done


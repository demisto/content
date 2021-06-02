#!/usr/bin/env bash
echo "$1"
# shellcheck disable=SC2164
cd "$1"
ls

echo "$2"
# shellcheck disable=SC2164
cd "$2"
ls
gsutil -m cp -r "$1" "$2"

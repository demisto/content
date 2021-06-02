#!/usr/bin/env bash
echo "$1"
echo "$2"

# shellcheck disable=SC2164
cd "$1"
ls
gsutil -m cp -r "$1" "$2"

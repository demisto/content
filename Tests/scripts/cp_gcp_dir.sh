#!/usr/bin/env bash
echo "$1"
echo "$2"
gsutil -m cp -r "$1" "$2"

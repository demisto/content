#!/usr/bin/env bash

echo "test!"
# Parsing the user inputs.

#while [[ "$#" -gt 0 ]]; do
#  case $1 in
#
#  -rb|--release-branch) _release_branch="$2"
#    shift
#    shift;;
#
#  esac
#done
#
#if [ -z "$_release_branch" ]; then
#    echo "Release branch was not provided."
#    exit 1
#fi
#
#echo "preparing to create the branch "$_release_branch
#
#git clone https://github.com/demisto/demisto-sdk.git /demisto-sdk
#cd /demisto-sdk
#git pull
#git checkout -b $_release_branch
#git push origin $_release_branch
#
#echo "the branch "$_release_branch" created successfully!"
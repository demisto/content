#!/usr/bin/env bash
set -e

ssh-keyscan github.com >> ~/.ssh/known_hosts

if [[ ! -d "content-test-data" ]]; then
    git clone git@github.com:demisto/content-test-data.git
fi
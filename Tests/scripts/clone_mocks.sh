#!/usr/bin/env bash
set -e

if [[ ! -d "content-test-data" ]]; then
    ssh-keyscan github.com >> ~/.ssh/known_hosts
    git clone git@github.com:demisto/content-test-data.git
  else
    cd content-test-data && git reset --hard && git pull -r
fi

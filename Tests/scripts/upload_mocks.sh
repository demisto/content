#!/usr/bin/env bash
set -e
cd content-test-data
git add Mocks/*.mock
git commit -m "Updated mock files from content build $1 - $2"
git push

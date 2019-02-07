#!/usr/bin/env bash
set -e
cd content-test-data
git add *.mock
git add *.log
git commit -m "Updated mock files from content build $1 - $2"
git push

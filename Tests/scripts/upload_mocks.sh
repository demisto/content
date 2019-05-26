#!/usr/bin/env bash
set -e

cd content-test-data
git add *
git commit -m "Updated mock files from content branch '$1' build number - $2" && git push --force || :

#!/usr/bin/env bash
FILE_TO_CHECK=$1
CONTENT_URL='https://github.com/demisto/content.git'

# Checks if there's any diff from master
git remote add mainRepo CONTENT_URL
git fetch mainRepo
if [[ `git diff mainRepo/master -- ${FILE_TO_CHECK}` ]]; then
    # Checks if part of the branch's changes
    if [[ -z `git diff mainRepo/master..."$CI_COMMIT_BRANCH" --name-only | grep ${FILE_TO_CHECK}` ]]; then
        echo "${FILE_TO_CHECK} has been changed. Merge from master"
        exit 1
    else
        echo "${FILE_TO_CHECK} is part of the branch changes, proceeding"
        exit 0
    fi
else
    echo "${FILE_TO_CHECK} is up to date!"
fi

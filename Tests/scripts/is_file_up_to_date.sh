#!/usr/bin/env bash
FILE_TO_CHECK=$1
BRANCH=$2

# Checks if there's any diff from master
if [[ $(git diff origin/master -- ${FILE_TO_CHECK}) ]]; then
    # Checks if part of the branch's changes
    if [[ -z $(git diff origin/master..."$BRANCH" --name-only -- ${FILE_TO_CHECK}) ]]; then
        echo "ERROR: ${FILE_TO_CHECK} has been changed. Merge from master"
        if [[ $BRANCH =~ pull/[0-9]+ ]]; then
          echo "Run ./Utils/git_pull_master_into_fork.sh or merge manually from upstream demisto content"
        fi

        exit 1
    else
        echo "${FILE_TO_CHECK} is part of the branch changes, proceeding"
        exit 0
    fi
else
    echo "${FILE_TO_CHECK} is up to date!"
fi

#!/usr/bin/env bash
FILE_TO_CHECK=$1
BRANCH=$2
SHOULD_CHECKOUT=$3

if [[ -n $BRANCH ]]; then
    BRANCH=$(git branch --show-current)
fi

# Checks if there's any diff from master
if [[ $(git diff origin/master -G"." -- ${FILE_TO_CHECK}) ]]; then
    # Checks if part of the branch's changes
    if [[ -z $(git diff origin/master..."$BRANCH" --name-only -- ${FILE_TO_CHECK}) ]]; then
        if [[ $SHOULD_CHECKOUT == "true" ]]; then
            # Checks out the file from origin/master
            echo "Checking out $FILE_TO_CHECK"
            git checkout origin/master -- ${FILE_TO_CHECK}
            exit 0
        fi
        if [[ -z "${CIRCLECI}" ]]; then
            # using printf & STDIN instead of command argument to support new lines in the message.
            # pick a ranadom cow-file
            printf "ERROR: %s has been changed.\nMerge from master" "${FILE_TO_CHECK}" | /usr/games/cowsay -n -f "$(ls /usr/share/cowsay/cows | shuf | head -1)"
        else
            # workaround for docker issue in CirlceCI
            printf "ERROR: %s has been changed.\nMerge from master" "${FILE_TO_CHECK}"
        fi

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

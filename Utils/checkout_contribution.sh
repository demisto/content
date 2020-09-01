#!/bin/bash
if (( $# < 1 )); then
    echo "please run ${0} <USER NAME>:<BRANCH NAME> [true]"
    echo by passing true as third argument this will update branch with origin/master
    echo for example:
    echo "${0} yaakovi:NewIntegrationBranch true"
    exit
fi

USER=$(echo $1 | cut -d ":" -f 1)
BRANCH=$(echo $1 | cut -d ":" -f 2)

if [[ $2 == "true" ]]; then
    git checkout master
    git pull
fi

git remote set-url $USER git@github.com:$USER/content.git
LOCAL_BRANCH_EXISTS=$(git show-branch --list "${USER}/${BRANCH}")
if [[ -z ${LOCAL_BRANCH_EXISTS} ]]; then
      git fetch "${USER}"
      git checkout -t "${USER}/${BRANCH}"
      git pull
else
      git checkout "${USER}/${BRANCH}"
      git switch "${BRANCH}"
      git pull
fi

if [[ $2 == "true" ]]; then
    echo merging branch with origin/master
    git merge origin/master
fi

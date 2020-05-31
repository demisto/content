#!/usr/bin/env bash

if [[ "$#" -lt 2 ]]; then
  echo "Usage: $0 <fork name> <branch name within the fork> "
  exit 1
fi


_fork_name=$1
_branch=$2

git remote add ${_fork_name} git@github.com:${_fork_name}/content.git
git fetch ${_fork_name}
git checkout -t ${_fork_name}/${_branch}
git pull
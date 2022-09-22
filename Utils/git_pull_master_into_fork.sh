#!/usr/bin/env bash

#Be aware, only contributors should run this script.

CONTENT_URL='https://github.com/demisto/content.git'

if [ -z "$1" ]
then
  CURRENT=$(git branch --show-current)
else
  CURRENT=$1
fi

(
  git remote add upstream_content $CONTENT_URL ||
  git remote set-url upstream_content $CONTENT_URL
) &&
git fetch upstream_content &&
git checkout master &&
git rebase upstream_content/master &&
git push -f origin master &&
git checkout $CURRENT &&
git pull origin master


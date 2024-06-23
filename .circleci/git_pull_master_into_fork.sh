#!/usr/bin/env bash
# this file has been deprecated and relocated to the contribution/utils directory
#Be aware, only contributors should run this script.

echo "This file has been deprecated and relocated to the contribution/utils directory"

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


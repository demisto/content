#!/usr/bin/env bash

CONTENT_URL='https://github.com/demisto/content.git'

if [ -z "$1" ]
then
  CURRENT=$(git branch --show-current)
  echo $CURRENT
else
  CURRENT=$1
  echo current is $CURRENT
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


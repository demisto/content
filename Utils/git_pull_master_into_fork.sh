#!/usr/bin/env bash

CONTENT_URL='https://github.com/demisto/content.git'
CURRENT=$(git branch --show-current)

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


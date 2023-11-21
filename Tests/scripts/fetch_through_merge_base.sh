#!/usr/bin/env bash

DEEPEN_LENGTH=${DEEPEN_LENGTH:-$GIT_DEPTH}

HEAD_REF=${1:-$(git rev-parse HEAD)}
BASE_REF=${2:-origin/master}
while [ -z "$(git merge-base "$BASE_REF" "$HEAD_REF" 2>/dev/null)" ]; do
  echo "Continuing fetch with a depth of $DEEPEN_LENGTH commits..."
  git fetch -q --deepen="$DEEPEN_LENGTH" origin;
  echo "git merge-base $BASE_REF $HEAD_REF"
done
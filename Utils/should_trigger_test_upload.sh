#!/usr/bin/env bash

DIFF_FILES_LIST=$(git diff origin/master...$CI_COMMIT_BRANCH --name-only)
IGNORED_FILES=(
    "Tests/conf.json"
    "Tests/known_words.txt"
)

for i in "${IGNORED_FILES[@]}"; do
    DIFF_FILES_LIST=${DIFF_FILES_LIST[*]/$i} 
done

SHOULD_SKIP_TEST=$(echo "${DIFF_FILES_LIST[*]}" | grep "Tests/\|Utils/")

if [ -z "$SHOULD_SKIP_TEST" ] ; then
    echo "No upload-flow related files were modified, skipping upload test"
    exit 0
fi

echo "Found modified files that should be tested in upload-flow"

#!/usr/bin/env bash

DIFF_FILES_LIST=$(git diff origin/master...$CI_COMMIT_BRANCH --name-only)
IGNORED_FILES=(
    "Tests/conf.json"
    "Tests/known_words.txt"
    "Utils/should_trigger_test_upload.sh"
)

for i in "${IGNORED_FILES[@]}"; do
    DIFF_FILES_LIST=${DIFF_FILES_LIST[*]/$i} 
done

echo "${DIFF_FILES_LIST[*]}" | grep "Tests/\|Utils/"
exit 0

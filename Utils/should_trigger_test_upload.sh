#!/usr/bin/env bash

DIFF_FILES_LIST=$(git diff origin/master...$CI_COMMIT_BRANCH --name-only)
IGNORED_FILES=(
    "Tests/conf.json"
    "Tests/known_words.txt"
)
echo "before for loop"
echo "${DIFF_FILES_LIST[*]}"
echo
for i in "${IGNORED_FILES[@]}"; do
    echo $i
    echo
    DIFF_FILES_LIST=${DIFF_FILES_LIST[*]/$i} 
done
echo "after for loop"
echo "${DIFF_FILES_LIST[*]}"
echo
SHOULD_SKIP_TEST=$(echo "${DIFF_FILES_LIST[*]}" | grep "Tests/\|Utils/")
echo "SHOULD_SKIP_TEST=$SHOULD_SKIP_TEST"
echo
if [ -z "$SHOULD_SKIP_TEST" ] ; then
    echo "No upload-flow related files were modified, skipping upload test"
    exit 0
fi

echo "Found modified files that should be tested in upload-flow"

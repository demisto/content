#!/usr/bin/env bash
if [[ $DEMISTO_SDK_NIGHTLY == "true" ]]; then
    echo "DEMISTO_SDK_NIGHTLY is set to true, Will run test-upload-flow"
    exit 0
fi
DIFF_FILES_LIST=$(git diff origin/master...$CI_COMMIT_BRANCH --name-only)
IGNORED_FILES=(
    "Tests/conf.json"
    "Tests/known_words.txt"
    "Utils/should_trigger_test_upload.sh"
    "Tests/tests_end_to_end_xsiam/README.md"
)

for i in "${IGNORED_FILES[@]}"; do
    DIFF_FILES_LIST=${DIFF_FILES_LIST[*]/$i} 
done

echo "${DIFF_FILES_LIST[*]}" | grep "Tests/\|Utils/"
exit 0

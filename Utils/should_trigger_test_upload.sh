#!/usr/bin/env bash
if [[ $DEMISTO_SDK_NIGHTLY == "true" ]]; then
    echo "DEMISTO_SDK_NIGHTLY is set to true, Will run test-upload-flow"
    exit 0
fi
DIFF_FILES_LIST=$(git diff origin/master...$CI_COMMIT_BRANCH --name-only)
GIT_DIFF_STATUS=$?

if [ $GIT_DIFF_STATUS -ne 0 ]; then
    echo "Error: git diff command failed with exit status: $GIT_DIFF_STATUS"
    exit 1
fi

IGNORED_FILES=(
    "Tests/conf.json"
    "Tests/known_words.txt"
    "Utils/should_trigger_test_upload.sh"
    "Tests/tests_e2e/content/xsiam/README.md",
    "Tests/tests_e2e/content/xsoar_saas/README.md"
)

for i in "${IGNORED_FILES[@]}"; do
    DIFF_FILES_LIST=${DIFF_FILES_LIST[*]/$i} 
done

echo "${DIFF_FILES_LIST[*]}" | grep -E "Tests/|Utils/|.gitlab/|poetry.lock|poetry.toml|pyproject.toml|package.json|package-lock.json|tox.ini|.pylintrc|.pre-commit-config_template.yaml"
exit 0

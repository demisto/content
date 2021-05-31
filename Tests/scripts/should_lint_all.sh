#!/usr/bin/env bash

# Simple script to check if build should run all lint. Will return empty result if no need or a string explaining why yes.

if [ -n "$NIGHTLY" ]; then
    echo "NIGHTLY env var is set: $NIGHTLY"
    exit 0
fi

if [ -n "$DEMISTO_SDK_NIGHTLY" ]; then
    echo "DEMISTO_SDK_NIGHTLY env var is set: $DEMISTO_SDK_NIGHTLY"
    exit 0
fi

if [ -n "$BUCKET_UPLOAD" ]; then
    echo "BUCKET_UPLOAD env var is set: $BUCKET_UPLOAD"
    exit 0
fi

if [ -z "$CIRCLE_BRANCH" ]; then
    # simply compare against origin/master. Local testing case..
    DIFF_COMPARE=origin/master
elif [ "$CIRCLE_BRANCH" == "master" ]; then
    # on master we use the range obtained from CIRCLE_COMPARE_URL
    # example of comapre url: https://github.com/demisto/content/compare/62f0bd03be73...1451bf0f3c2a
    # if CIRCLE_COMPARE_URL is not set we use last commit
    if [ -z "$CIRCLE_COMPARE_URL" ]; then
        DIFF_COMPARE="HEAD^1...HEAD"
    else
        DIFF_COMPARE=$(echo "$CIRCLE_COMPARE_URL" | sed 's:^.*/compare/::g')    
        if [ -z "${DIFF_COMPARE}" ]; then
            echo "Failed: extracting diff compare from CIRCLE_COMPARE_URL: ${CIRCLE_COMPARE_URL}. Return true (0)"
            exit 0
        fi
    fi
else
    DIFF_COMPARE=origin/master...${CIRCLE_BRANCH}
fi

# test if any of the lint libraries has been updated

DIFF_RES=$(git diff  "$DIFF_COMPARE" -- dev-requirements-py*  | grep -E '\+(flake8|mypy|demisto-sdk|bandit|vulture)' )

if [[ -n "$DIFF_RES" ]]; then
    echo -e "Found modified dependency packages:\n$DIFF_RES"
    exit 0
fi

# test if CommonServerPython has been modified
DIFF_RES=$(git diff  "$DIFF_COMPARE" -- Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)
if [[ -n "$DIFF_RES" ]]; then
    echo -e "CommonServerPython.py has been modified"
    exit 0
fi

# test if CommonServerPowerShell has been modified
DIFF_RES=$(git diff  "$DIFF_COMPARE" -- Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1)
if [[ -n "$DIFF_RES" ]]; then
    echo -e "CommonServerPowerShell.ps1 has been modified"
    exit 0
fi

# test if CommonServer has been modified
DIFF_RES=$(git diff  "$DIFF_COMPARE" -- Packs/Base/Scripts/script-CommonServer.yml)
if [[ -n "$DIFF_RES" ]]; then
    echo -e "CommonServer.yml has been modified"
    exit 0
fi

# test if CommonServerPython has been modified
DIFF_RES=$(git diff  "$DIFF_COMPARE" -- Tests/demistomock/demistomock.py)
if [[ -n "$DIFF_RES" ]]; then
    echo -e "demistomock.py has been modified"
    exit 0
fi


# all tests passed return 0
exit 0

#!/usr/bin/env bash

# Simple script to check if build should run all lint

if [ -n "$NIGHTLY" ]; then
    echo "NIGHTLY env var is set: $NIGHTLY"
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

DIFF_RES=$(git diff  "$DIFF_COMPARE" -- dev-requirements-py*  | grep -E '\+(flake8|mypy|demisto-sdk|bandit)' )

if [[ -n "$DIFF_RES" ]]; then
    echo -e "Found modified dependency packages:\n$DIFF_RES"
    exit 0
fi

# all tests passed return 1
exit 1

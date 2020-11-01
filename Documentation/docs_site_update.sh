#!/usr/bin/env bash

# Simple script to check if build should run all lint. Will return empty result if no need or a string explaining why yes.

if [ -n "$NIGHTLY" ]; then
    echo "NIGHTLY env var is set: $NIGHTLY. Skipping Content Docs Update"
    exit 0
fi

if [ -n "$INSTANCE_TESTS" ]; then
    echo "INSTANCE_TESTS env var is set: $INSTANCE_TESTS. Skipping Content Docs Update"
    exit 0
fi

if [ -z "$CIRCLE_BRANCH" ]; then
    # simply compare against origin/master. Local testing case..
    DIFF_COMPARE=origin/master  # disable-secrets-detection
elif [ "$CIRCLE_BRANCH" == "master" ]; then
    # on master we use the range obtained from CIRCLE_COMPARE_URL
    # example of comapre url: https://github.com/demisto/content/compare/62f0bd03be73...1451bf0f3c2a
    # if CIRCLE_COMPARE_URL is not set we use last commit
    if [ -z "$CIRCLE_COMPARE_URL" ]; then
        DIFF_COMPARE="HEAD^1...HEAD"
    else
        DIFF_COMPARE=$(echo "$CIRCLE_COMPARE_URL" | sed 's:^.*/compare/::g')
        if [ -z "${DIFF_COMPARE}" ]; then
            echo "Failed: extracting diff compare from CIRCLE_COMPARE_URL: ${CIRCLE_COMPARE_URL}. Fail.."
            exit 1
        fi
    fi
else
    DIFF_COMPARE=origin/master...${CIRCLE_BRANCH}
fi

DIFF_RES=$(git diff --name-only  "$DIFF_COMPARE"  | grep -E '(Integrations|Scripts|Playbooks)/.*README.md' )

if [[ -n "$DIFF_RES" ]]; then
    echo -e "Found modified README files:\n$DIFF_RES"
    if [ "$CIRCLE_BRANCH" == "master" ]; then
        if [ -n "${NETLIFY_BUILD_HOOK}" ]; then
            curl -X POST -d '{}' "${NETLIFY_BUILD_HOOK}?trigger_title=triggered+by+Content+Reference+Docs+Update"
            echo "Done triggering content docs build!"
        else
            echo "NETLIFY_BUILD_HOOK not set!!!"
        fi
    else
        echo "Not on master. Skipping update. Content Docs will be updated when merged to master."
    fi
else
    echo "No modified README files found. Content Docs are not updated."
fi
exit 0

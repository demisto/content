#!/bin/bash

# Default value
FAIL_IF_NOT_FOUND=false

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        -f|--fail)
            FAIL_IF_NOT_FOUND=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ $CI_COMMIT_BRANCH = "master" ]]; then
    if [[ $BUCKET_UPLOAD == "true" ]]; then
        echo "The relevant master commit SHA is the last upload commit"
        export PREVIOUS_MASTER_SHA=$LAST_UPLOAD_COMMIT
    else
        echo "Getting the previous master commit SHA"
        export PREVIOUS_MASTER_SHA=$(git rev-parse HEAD^)
    fi
else
    echo "Getting the commit SHA of the common ancestor of current branch and master branch"
    export PREVIOUS_MASTER_SHA=$(git merge-base HEAD origin/master)
fi

if [ -z "$PREVIOUS_MASTER_SHA" ] && [ "$FAIL_IF_NOT_FOUND" = true ]; then
    echo "Previous master commit SHA not found in branch history"
    exit 1
else
    echo "PREVIOUS_MASTER_SHA = $PREVIOUS_MASTER_SHA"
fi

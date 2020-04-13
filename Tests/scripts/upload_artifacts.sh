#!/usr/bin/env bash

# exit on errors
set -e

# Build uploads artifacts dir to artifacts bucket

CIRCLE_BRANCH=${CIRCLE_BRANCH:-unknown}
ARTIFACTS_DIR=${ARTIFACTS_DIR:-artifacts}
CIRCLE_NODE_INDEX=${CIRCLE_NODE_INDEX:-0}

if [[ -z "$CIRCLE_BUILD_NUM" ]]; then
    echo "CIRCLE_BUILD_NUM not set aborting!"
    exit 1
fi

if [[ -z "$GCS_ARTIFACTS_BUCKET" ]]; then
    echo "GCS_ARTIFACTS_BUCKET not set aborting!"
    exit 1
fi

if [[ -z "$GCS_ARTIFACTS_KEY" ]]; then
    echo "GCS_ARTIFACTS_KEY not set aborting!"
    exit 1
fi

KF=$(mktemp)
echo "$GCS_ARTIFACTS_KEY" > "$KF"
gcloud auth activate-service-account --key-file="$KF" > auth.out 2>&1
rm "$KF"
TARGET_PATH="content/$CIRCLE_BRANCH/$CIRCLE_BUILD_NUM/$CIRCLE_NODE_INDEX"
echo "auth loaded. uploading files at: $ARTIFACTS_DIR to target path: $TARGET_PATH ..."
gsutil -m cp -r "$ARTIFACTS_DIR" "gs://$GCS_ARTIFACTS_BUCKET/$TARGET_PATH"

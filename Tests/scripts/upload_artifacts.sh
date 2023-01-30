#!/usr/bin/env bash

# exit on errors
set -e

# Build uploads artifacts dir to artifacts bucket
BRANCH=${CI_COMMIT_BRANCH:-unknown}
ARTIFACTS_DIR=${ARTIFACTS_FOLDER:-artifacts}

# build type is staging if ID_SET doesn't exist
ID_SET=$ARTIFACTS_FOLDER/id_set.json
STAGING_SUFFIX=""
if [ ! -f "$ID_SET" ]; then
    echo "ID_SET file not found at $ID_SET"
    STAGING_SUFFIX="_staging"
fi


if [[ ! -d "$ARTIFACTS_DIR" ]]; then
    echo "Directory [$ARTIFACTS_DIR] not found. Nothing to upload. Skipping!"
    exit 0
fi

if [[ -z "$(ls -A ${ARTIFACTS_DIR})" ]]; then
    echo "Directory [$ARTIFACTS_DIR] is empty. Nothing to upload. Skipping!"
    exit 0
fi

if [[ "$BRANCH" =~ pull/[0-9]+ ]]; then
    echo "Running on remote fork. Skipping!"
    exit 0
fi

if [[ -z "$CI_PIPELINE_ID" ]]; then
    echo "CI_PIPELINE_ID not set aborting!"
    exit 1
fi

if [[ -z "$GCS_ARTIFACTS_BUCKET" ]]; then
    echo "GCS_ARTIFACTS_BUCKET not set aborting!"
    exit 1
fi

if [[ ! -f "$GCS_ARTIFACTS_KEY" ]]; then
    echo "GCS_ARTIFACTS_KEY not set aborting!"
    exit 1
fi

gcloud auth activate-service-account --key-file=$GCS_ARTIFACTS_KEY > auth.out 2>&1
TARGET_PATH="content/$BRANCH/$CI_PIPELINE_ID$STAGING_SUFFIX"
echo "auth loaded. uploading files at: $ARTIFACTS_DIR to target path: $TARGET_PATH ..."
gsutil -m cp -z html,md,json,log,txt -r "$ARTIFACTS_DIR" "gs://$GCS_ARTIFACTS_BUCKET/$TARGET_PATH"

#!/usr/bin/env bash

# exit on errors
set -e

CI_COMMIT_BRANCH=${CI_COMMIT_BRANCH:-unknown}
CI_JOB_ID=${CI_JOB_ID:-00000}
PACK_ARTIFACTS="${ARTIFACTS_FOLDER_SERVER_TYPE}/content_packs.zip"
EXTRACT_FOLDER=$(mktemp -d)


if [[ ! -f "$GCS_MARKET_KEY" ]]; then
    echo "GCS_MARKET_KEY not set aborting!"
    exit 1
fi

if [[ -z "$3" ]]; then
  MARKETPLACE_TYPE="xsoar"  # The default is "marketplace-dist"
else
  MARKETPLACE_TYPE=$3

  if [[ "$MARKETPLACE_TYPE" == "marketplacev2" ]]; then
    GCS_PRODUCTION_BUCKET=$GCS_PRODUCTION_V2_BUCKET

  elif [[ "$MARKETPLACE_TYPE" == "xpanse" ]]; then
    GCS_PRODUCTION_BUCKET=$GCS_PRODUCTION_XPANSE_BUCKET

  elif [[ "$MARKETPLACE_TYPE" == "xsoar_saas" ]]; then
    GCS_PRODUCTION_BUCKET=$GCS_PRODUCTION_XSOAR_SAAS_BUCKET
  fi
fi
# We can freely use these buckets since its only reading the prod to the circle-ci bucket.

echo "Preparing content packs for testing ..."
gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" >> "${ARTIFACTS_FOLDER_SERVER_TYPE}/logs/gcloud_auth.log" 2>&1
echo "Auth loaded successfully."

# ====== BUILD CONFIGURATION ======
GCS_BUILD_BUCKET="marketplace-ci-build"
BUILD_BUCKET_PATH="content/builds/$CI_COMMIT_BRANCH/$CI_PIPELINE_ID$STAGING_SUFFIX/$MARKETPLACE_TYPE"
BUILD_BUCKET_PACKS_DIR_PATH="$BUILD_BUCKET_PATH/content/packs"
BUILD_BUCKET_CONTENT_DIR_FULL_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PATH/content"
BUILD_BUCKET_FULL_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PATH"
BUILD_BUCKET_PACKS_DIR_FULL_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PACKS_DIR_PATH"
if [[ -z "$CREATE_DEPENDENCIES_ZIP" ]]; then
  CREATE_DEPENDENCIES_ZIP=false
fi

# ====== BUCKET CONFIGURATION  ======
if [[ -z "$1" ]]; then
  GCS_MARKET_BUCKET=$GCS_PRODUCTION_BUCKET
else
  GCS_MARKET_BUCKET=$1
fi

if [[ "$GCS_MARKET_BUCKET" == "$GCS_PRODUCTION_BUCKET" ]]; then  # case 1: a prod upload, the source is in the prod bucket
  SOURCE_PATH="content"
else
  if [[ -z "$2" ]]; then  # case 2: a test upload, the source is of a new target bucket, need to copy from prod to that target
    SOURCE_PATH="upload-flow/builds/$CI_COMMIT_BRANCH/$CI_PIPELINE_ID/content"
    # ====== UPDATING TESTING BUCKET ======
    echo "Copying production bucket files at: gs://$GCS_PRODUCTION_BUCKET/content to dev bucket at path: gs://$GCS_MARKET_BUCKET/$SOURCE_PATH"
    gsutil -m cp -r "gs://$GCS_PRODUCTION_BUCKET/content" "gs://$GCS_MARKET_BUCKET/$SOURCE_PATH" >> "${ARTIFACTS_FOLDER_SERVER_TYPE}/logs/Prepare_Content_Packs_For_Testing_gsutil.log" 2>&1
    echo "Finished copying successfully."
    # ====== UPDATING TESTING BUCKET ======
  else  # case 3: a test upload, the source is of an exiting target bucket, no need to copy from the prod bucket
    SOURCE_PATH=$2  # should look like: "upload-flow/builds/$CI_COMMIT_BRANCH/$CI_PIPELINE_ID/content"

  fi
fi

echo "Copying master files at: gs://$GCS_MARKET_BUCKET/$SOURCE_PATH to build bucket at target path: gs://$BUILD_BUCKET_CONTENT_DIR_FULL_PATH"
gsutil -m cp -r "gs://$GCS_MARKET_BUCKET/$SOURCE_PATH" "gs://$BUILD_BUCKET_CONTENT_DIR_FULL_PATH" >> "${ARTIFACTS_FOLDER_SERVER_TYPE}/logs/Prepare_Content_Packs_For_Testing_gsutil.log" 2>&1
echo "Finished copying successfully."
echo "$BUILD_BUCKET_PATH"
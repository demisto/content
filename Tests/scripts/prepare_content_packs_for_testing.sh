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

CONTENT_PACKS_TO_UPLOAD_FILE="${ARTIFACTS_FOLDER_SERVER_TYPE}/content_packs_to_upload.txt"
CONTENT_PACKS_TO_UPLOAD=$(paste -sd, "${CONTENT_PACKS_TO_UPLOAD_FILE}")
if [[ -z "${CONTENT_PACKS_TO_UPLOAD}" ]]; then
  echo "Did not get content packs to update in the bucket. Skipping upload step."
  exit 0
fi

echo "BUCKET_UPLOAD = $BUCKET_UPLOAD, FORCE_BUCKET_UPLOAD = $FORCE_BUCKET_UPLOAD, PACKS_TO_UPLOAD = $PACKS_TO_UPLOAD"
echo "Uploading the following content packs: ${CONTENT_PACKS_TO_UPLOAD}"

# Workaround for the SDK hard-coded path.
mv "${ARTIFACTS_FOLDER}/markdown_images.json" "${ARTIFACTS_FOLDER_SERVER_TYPE}/markdown_images.json"

UPLOAD_SPECIFIC_PACKS=false
if [ -z "${BUCKET_UPLOAD}" ] && [ -z "${FORCE_BUCKET_UPLOAD}" ]; then
  # PR / nightly build
  python3 ./Tests/Marketplace/upload_packs.py -pa "${PACK_ARTIFACTS}" -d "${ARTIFACTS_FOLDER_SERVER_TYPE}/packs_dependencies.json" --artifacts-folder-server-type "${ARTIFACTS_FOLDER_SERVER_TYPE}" -e $EXTRACT_FOLDER -b $GCS_BUILD_BUCKET -s "$GCS_MARKET_KEY" -n "$CI_PIPELINE_ID" -pn "${CONTENT_PACKS_TO_UPLOAD}" -p $UPLOAD_SPECIFIC_PACKS -o false -sb $BUILD_BUCKET_PACKS_DIR_PATH -k $PACK_SIGNING_KEY -rt false -bu false -c $CI_COMMIT_BRANCH -f false -dz "$CREATE_DEPENDENCIES_ZIP" -mp "$MARKETPLACE_TYPE"
  echo "Finished updating content packs successfully."
else
  # upload-flow build - production / force / specific packs
  GCS_PRIVATE_BUCKET="marketplace-dist-private"
  if [ -n "${PACKS_TO_UPLOAD}" ] && [ $FORCE_BUCKET_UPLOAD == "false" ]; then
    # In case there are given pack ids to upload and it is not a force
    echo "Upload the following specific packs: ${PACKS_TO_UPLOAD}"
    UPLOAD_SPECIFIC_PACKS=true
  fi
  python3 ./Tests/Marketplace/upload_packs.py -pa "${PACK_ARTIFACTS}" -d "${ARTIFACTS_FOLDER_SERVER_TYPE}/packs_dependencies.json" --artifacts-folder-server-type "${ARTIFACTS_FOLDER_SERVER_TYPE}" -e $EXTRACT_FOLDER -b $GCS_BUILD_BUCKET -s "$GCS_MARKET_KEY" -n $CI_PIPELINE_ID -pn "${CONTENT_PACKS_TO_UPLOAD}" -p $UPLOAD_SPECIFIC_PACKS -o $OVERRIDE_ALL_PACKS -sb $BUILD_BUCKET_PACKS_DIR_PATH -k $PACK_SIGNING_KEY -rt true -bu $BUCKET_UPLOAD -pb "$GCS_PRIVATE_BUCKET" -c $CI_COMMIT_BRANCH -f $FORCE_BUCKET_UPLOAD -dz "$CREATE_DEPENDENCIES_ZIP" -mp "$MARKETPLACE_TYPE"

  if [ -f "${ARTIFACTS_FOLDER_SERVER_TYPE}/index.json" ]; then
    gsutil cp -z json "${ARTIFACTS_FOLDER_SERVER_TYPE}/index.json" "gs://$BUILD_BUCKET_PACKS_DIR_FULL_PATH"
  else
    echo "Skipping uploading ${ARTIFACTS_FOLDER_SERVER_TYPE}/index.json file, it doesn't exist."
  fi

  echo "Finished updating content packs successfully."
fi

echo -e "\nBrowse to the build bucket with this address:"
echo -e "https://console.cloud.google.com/storage/browser/$BUILD_BUCKET_FULL_PATH\n"
echo "Finished preparing content packs for testing successfully."

echo -e "\nIf you want to connect this build bucket to your test machine, add this server configs:"
echo "marketplace.bootstrap.bypass.url: https://storage.googleapis.com/$BUILD_BUCKET_FULL_PATH"
echo "jobs.marketplacepacks.schedule: 1m"

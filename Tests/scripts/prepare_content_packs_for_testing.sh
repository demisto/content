#!/usr/bin/env bash

# exit on errors
set -e

CI_COMMIT_BRANCH=${CI_COMMIT_BRANCH:-unknown}
CI_BUILD_ID=${CI_BUILD_ID:-00000}
PACK_ARTIFACTS=$ARTIFACTS_FOLDER/content_packs.zip
ID_SET=$ARTIFACTS_FOLDER/id_set.json
EXTRACT_FOLDER=$(mktemp -d)

if [[ ! -f "$GCS_MARKET_KEY" ]]; then
    echo "GCS_MARKET_KEY not set aborting!"
    exit 1
fi

if [[ -z "$3" ]]; then
  MARKETPLACE_TYPE="xsoar"
else
  MARKETPLACE_TYPE=$3
  if [[ "$MARKETPLACE_TYPE" == "marketplacev2" ]]; then
    GCS_PRODUCTION_BUCKET=$GCS_PRODUCTION_V2_BUCKET
  fi
fi

echo "Preparing content packs for testing ..."
gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" > auth.out 2>&1
echo "Auth loaded successfully."

# ====== BUILD CONFIGURATION ======
GCS_BUILD_BUCKET="marketplace-ci-build"
BUILD_BUCKET_PATH="content/builds/$CI_COMMIT_BRANCH/$CI_PIPELINE_ID/$MARKETPLACE_TYPE"
BUILD_BUCKET_PACKS_DIR_PATH="$BUILD_BUCKET_PATH/content/packs"
BUILD_BUCKET_CONTENT_DIR_FULL_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PATH/content"
BUILD_BUCKET_FULL_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PATH"
BUILD_BUCKET_PACKS_DIR_FULL_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PACKS_DIR_PATH"

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
    echo "Copying production bucket files at: gs://$GCS_PRODUCTION_BUCKET/content to testing bucket at path: gs://$GCS_MARKET_BUCKET/$SOURCE_PATH ..."
    gsutil -m cp -r "gs://$GCS_PRODUCTION_BUCKET/content" "gs://$GCS_MARKET_BUCKET/$SOURCE_PATH" > "$ARTIFACTS_FOLDER/logs/Prepare Content Packs For Testing gsutil.log" 2>&1
    echo "Finished copying successfully."
    # ====== UPDATING TESTING BUCKET ======
  else  # case 3: a test upload, the source is of an exiting target bucket, no need to copy from the prod bucket
    SOURCE_PATH=$2  # should look like: "upload-flow/builds/$CI_COMMIT_BRANCH/$CI_PIPELINE_ID/content"

  fi

fi

echo "Copying master files at: gs://$GCS_MARKET_BUCKET/$SOURCE_PATH to target path: gs://$BUILD_BUCKET_CONTENT_DIR_FULL_PATH ..."
gsutil -m cp -r "gs://$GCS_MARKET_BUCKET/$SOURCE_PATH" "gs://$BUILD_BUCKET_CONTENT_DIR_FULL_PATH" > "$ARTIFACTS_FOLDER/logs/Prepare Content Packs For Testing gsutil.log" 2>&1
echo "Finished copying successfully."

if [ -z "${BUCKET_UPLOAD}" ]; then
    echo "Updating modified content packs in the bucket ..."
    CONTENT_PACKS_TO_INSTALL_FILE="$ARTIFACTS_FOLDER/content_packs_to_install.txt"
  if [ ! -f $CONTENT_PACKS_TO_INSTALL_FILE ]; then
    echo "Could not find file $CONTENT_PACKS_TO_INSTALL_FILE."
  else
    CONTENT_PACKS_TO_INSTALL=$(paste -sd, $CONTENT_PACKS_TO_INSTALL_FILE)
    if [[ -z "$CONTENT_PACKS_TO_INSTALL" ]]; then
      echo "Did not get content packs to update in the bucket."
    else
      echo "Updating the following content packs: $CONTENT_PACKS_TO_INSTALL ..."
      python3 ./Tests/Marketplace/upload_packs.py -pa $PACK_ARTIFACTS -idp $ID_SET -d $ARTIFACTS_FOLDER/packs_dependencies.json -e $EXTRACT_FOLDER -b $GCS_BUILD_BUCKET -s "$GCS_MARKET_KEY" -n $CI_PIPELINE_ID -p $CONTENT_PACKS_TO_INSTALL -o true -sb $BUILD_BUCKET_PACKS_DIR_PATH -k $PACK_SIGNING_KEY -rt false -bu false -c $CI_COMMIT_BRANCH -f false -dz "$CREATE_DEPENDENCIES_ZIP" -mp "$MARKETPLACE_TYPE"
      echo "Finished updating content packs successfully."
    fi
  fi
else
  # In Upload-Flow, we exclude test-pbs in the zipped packs
  REMOVE_PBS=true
  BUCKET_UPLOAD_FLOW=true
  GCS_PRIVATE_BUCKET="marketplace-dist-private"
  if [ -n "${FORCE_PACK_UPLOAD}" ] && [ -n "${PACKS_TO_UPLOAD}" ]; then
    # In case the workflow is force upload, we override the forced packs
    echo "Force uploading to production the following packs: ${PACKS_TO_UPLOAD}"
    OVERRIDE_ALL_PACKS=true
    PACKS_LIST="${PACKS_TO_UPLOAD}"
    IS_FORCE_UPLOAD=true
  else
    # In case of a regular upload flow, the upload_packs script will decide which pack to upload or not, thus it is
    # given with all the packs, we don't override packs to not force upload a pack
    echo "Updating all content packs for upload packs to production..."
    PACKS_LIST="all"
    IS_FORCE_UPLOAD=false
  fi
  python3 ./Tests/Marketplace/upload_packs.py -pa $PACK_ARTIFACTS -idp $ID_SET -d $ARTIFACTS_FOLDER/packs_dependencies.json -e $EXTRACT_FOLDER -b $GCS_BUILD_BUCKET -s "$GCS_MARKET_KEY" -n $CI_PIPELINE_ID -p "$PACKS_LIST" -o $OVERRIDE_ALL_PACKS -sb $BUILD_BUCKET_PACKS_DIR_PATH -k $PACK_SIGNING_KEY -rt $REMOVE_PBS -bu $BUCKET_UPLOAD_FLOW -pb "$GCS_PRIVATE_BUCKET" -c $CI_COMMIT_BRANCH -f $IS_FORCE_UPLOAD -dz "$CREATE_DEPENDENCIES_ZIP" -mp "$MARKETPLACE_TYPE"

  if [ -f "$ARTIFACTS_FOLDER/index.json" ]; then
    gsutil cp -z json "$ARTIFACTS_FOLDER/index.json" "gs://$BUILD_BUCKET_PACKS_DIR_FULL_PATH"
  else
    echo "Skipping uploading index.json file."
  fi
  if [ -f "$ARTIFACTS_FOLDER/corepacks.json" ]; then
    gsutil cp -z json "$ARTIFACTS_FOLDER/corepacks.json" "gs://$BUILD_BUCKET_PACKS_DIR_FULL_PATH"
  else
    echo "Skipping uploading corepacks.json file."
  fi
  if [ -f $ID_SET ]; then
    gsutil cp -z json $ID_SET "gs://$BUILD_BUCKET_CONTENT_DIR_FULL_PATH"
  else
    echo "Skipping uploading id_set.json file."
  fi

  echo "Finished updating content packs successfully."
fi

echo -e "\nBrowse to the build bucket with this address:"
echo -e "https://console.cloud.google.com/storage/browser/$BUILD_BUCKET_FULL_PATH\n"
echo "Finished preparing content packs for testing successfully."

echo -e "\nIf you want to connect this build bucket to your test machine, add this server configs:"
echo "marketplace.bootstrap.bypass.url: https://storage.googleapis.com/$BUILD_BUCKET_FULL_PATH"
echo "jobs.marketplacepacks.schedule: 1m"

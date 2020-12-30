#!/usr/bin/env bash

# exit on errors
set -e

CIRCLE_BRANCH=${CIRCLE_BRANCH:-unknown}
CIRCLE_BUILD_NUM=${CIRCLE_BUILD_NUM:-00000}
CIRCLE_ARTIFACTS=${CIRCLE_ARTIFACTS}
PACK_ARTIFACTS=$CIRCLE_ARTIFACTS/content_packs.zip
ID_SET=$CIRCLE_ARTIFACTS/id_set.json
EXTRACT_FOLDER=$(mktemp -d)

if [[ -z "$GCS_MARKET_KEY" ]]; then
    echo "GCS_MARKET_KEY not set aborting!"
    exit 1
fi

echo "Preparing content packs for testing ..."

KF=$(mktemp)
echo "$GCS_MARKET_KEY" > "$KF"
gcloud auth activate-service-account --key-file="$KF" > auth.out 2>&1
echo "Auth loaded successfully."

# ====== BUILD CONFIGURATION ======
GCS_BUILD_BUCKET="marketplace-ci-build"
BUILD_BUCKET_PATH="content/builds/$CIRCLE_BRANCH/$CIRCLE_BUILD_NUM"
TARGET_PATH="$BUILD_BUCKET_PATH/content/packs"
CONTENT_FULL_TARGET_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PATH/content"
BUCKET_FULL_TARGET_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PATH"

# ====== PRODUCTION CONFIGURATION ======
GCS_MARKET_BUCKET="marketplace-dist"
SOURCE_PATH="content"

echo "Copying master files at: gs://$GCS_MARKET_BUCKET/$SOURCE_PATH to target path: gs://$CONTENT_FULL_TARGET_PATH ..."
gsutil -m cp -r "gs://$GCS_MARKET_BUCKET/$SOURCE_PATH" "gs://$CONTENT_FULL_TARGET_PATH" > "$CIRCLE_ARTIFACTS/logs/Prepare Content Packs For Testing.log" 2>&1
echo "Finished copying successfully."

if [ ! -n "${NIGHTLY}" ] && [ ! -n "${BUCKET_UPLOAD}" ]; then
    echo "Updating modified content packs in the bucket ..."
    CONTENT_PACKS_TO_INSTALL_FILE="./Tests/content_packs_to_install.txt"
  if [ ! -f $CONTENT_PACKS_TO_INSTALL_FILE ]; then
    echo "Could not find file $CONTENT_PACKS_TO_INSTALL_FILE."
  else
    CONTENT_PACKS_TO_INSTALL=$(paste -sd, $CONTENT_PACKS_TO_INSTALL_FILE)
    if [[ -z "$CONTENT_PACKS_TO_INSTALL" ]]; then
      echo "Did not get content packs to update in the bucket."
    else
      echo "Updating the following content packs: $CONTENT_PACKS_TO_INSTALL ..."
      python3 ./Tests/Marketplace/upload_packs.py -a $PACK_ARTIFACTS -d $CIRCLE_ARTIFACTS/packs_dependencies.json -e $EXTRACT_FOLDER -b $GCS_BUILD_BUCKET -s $KF -n $CIRCLE_BUILD_NUM -p $CONTENT_PACKS_TO_INSTALL -o true -sb $TARGET_PATH -k $PACK_SIGNING_KEY -rt false --id_set_path $ID_SET -bu false -c $CIRCLE_BRANCH -f false
      echo "Finished updating content packs successfully."
    fi
  fi
else
  IS_FORCE_UPLOAD=false
  if [ -n "${NIGHTLY}" ]; then
    echo "Updating all content packs for nightly build..."
    # In content nightly we include test-pbs in the zipped packs, we override all packs and we test all packs in the repo
    REMOVE_PBS=false
    OVERRIDE_ALL_PACKS=true
    BUCKET_UPLOAD_FLOW=false
    PACKS_LIST="all"
  elif [ -n "${BUCKET_UPLOAD}" ]; then
      # In bucket upload flow, we exclude test-pbs in the zipped packs
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
      OVERRIDE_ALL_PACKS=false
      PACKS_LIST="all"
    fi
  fi
  python3 ./Tests/Marketplace/upload_packs.py -a $PACK_ARTIFACTS -d $CIRCLE_ARTIFACTS/packs_dependencies.json -e $EXTRACT_FOLDER -b $GCS_BUILD_BUCKET -s $KF -n $CIRCLE_BUILD_NUM -p "$PACKS_LIST" -o $OVERRIDE_ALL_PACKS -sb $TARGET_PATH -k $PACK_SIGNING_KEY -rt $REMOVE_PBS --id_set_path $ID_SET -bu $BUCKET_UPLOAD_FLOW -pb "$GCS_PRIVATE_TESTING_BUCKET" -c $CIRCLE_BRANCH -f $IS_FORCE_UPLOAD
  echo "Finished updating content packs successfully."
fi

echo -e "\nBrowse to the build bucket with this address:"
echo -e "https://console.cloud.google.com/storage/browser/$BUCKET_FULL_TARGET_PATH\n"
echo "Finished preparing content packs for testing successfully."

echo -e "\nIf you want to connect this build bucket to your test machine, add this server configs:"
echo "marketplace.bootstrap.bypass.url: https://storage.googleapis.com/$BUCKET_FULL_TARGET_PATH"
echo "jobs.marketplacepacks.schedule: 1m"
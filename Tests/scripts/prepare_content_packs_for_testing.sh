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

GCS_MARKET_BUCKET="marketplace-dist"
GCS_BUILD_BUCKET="marketplace-ci-build"
SOURCE_PATH="content/packs"
BUILD_BUCKET_PATH="content/builds/$CIRCLE_BRANCH/$CIRCLE_BUILD_NUM"
TARGET_PATH="$BUILD_BUCKET_PATH/content/packs"
PACKS_FULL_TARGET_PATH="$GCS_BUILD_BUCKET/$TARGET_PATH"
BUCKET_FULL_TARGET_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PATH"
echo "Copying master files at: $SOURCE_PATH to target path: gs://$PACKS_FULL_TARGET_PATH ..."
gsutil -m cp -r "gs://$GCS_MARKET_BUCKET/$SOURCE_PATH" "gs://$PACKS_FULL_TARGET_PATH" > "$CIRCLE_ARTIFACTS/logs/Prepare Content Packs For Testing.log" 2>&1
echo "Finished copying successfully."

echo "Updating modified content packs in the bucket ..."

if [ ! -n "${NIGHTLY}" ]; then
    CONTENT_PACKS_TO_INSTALL_FILE="./Tests/content_packs_to_install.txt"
  if [ ! -f $CONTENT_PACKS_TO_INSTALL_FILE ]; then
    echo "Could not find file $CONTENT_PACKS_TO_INSTALL_FILE."
  else
    CONTENT_PACKS_TO_INSTALL=$(paste -sd, $CONTENT_PACKS_TO_INSTALL_FILE)
    if [[ -z "$CONTENT_PACKS_TO_INSTALL" ]]; then
      echo "Did not get content packs to update in the bucket."
    else
      echo "Updating the following content packs: $CONTENT_PACKS_TO_INSTALL ..."
      python3 ./Tests/Marketplace/upload_packs.py -a $PACK_ARTIFACTS -d $CIRCLE_ARTIFACTS/packs_dependencies.json -e $EXTRACT_FOLDER -b $GCS_BUILD_BUCKET -s $KF -n $CIRCLE_BUILD_NUM -p $CONTENT_PACKS_TO_INSTALL -o -sb $TARGET_PATH -k $PACK_SIGNING_KEY -rt false --id_set_path $ID_SET
      echo "Finished updating content packs successfully."
    fi
  fi
else
  echo "Updating all content packs for nightly build..."
  python3 ./Tests/Marketplace/upload_packs.py -a $PACK_ARTIFACTS -d $CIRCLE_ARTIFACTS/packs_dependencies.json -e $EXTRACT_FOLDER -b $GCS_BUILD_BUCKET -s $KF -n $CIRCLE_BUILD_NUM -o -sb $TARGET_PATH -k $PACK_SIGNING_KEY -rt false --id_set_path $ID_SET
  echo "Finished updating content packs successfully."
fi

#echo "Normalizing images paths to build bucket ..."
#python3 ./Tests/Marketplace/normalize_gcs_paths.py -sb $TARGET_PATH -b $GCS_BUILD_BUCKET -s $KF
#echo "Finished normalizing images paths successfully."

echo -e "\nBrowse to the build bucket with this address:"
echo -e "https://console.cloud.google.com/storage/browser/$BUCKET_FULL_TARGET_PATH\n"
echo "Finished preparing content packs for testing successfully."

echo -e "\nIf you want to connect this build bucket to your test machine, add this server config:"
echo "marketplace.bootstrap.bypass.url: https://storage.googleapis.com/$BUCKET_FULL_TARGET_PATH"

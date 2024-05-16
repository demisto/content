#!/usr/bin/env bash

# exit on errors
set -e
# ====== BUILD CONFIGURATION ======
CI_COMMIT_BRANCH=${CI_COMMIT_BRANCH:-unknown}
CI_JOB_ID=${CI_JOB_ID:-00000}
PACK_ARTIFACTS="${ARTIFACTS_FOLDER_SERVER_TYPE}/content_packs.zip"
EXTRACT_FOLDER=$(mktemp -d)
if [[ -z "$1" ]]; then
  MARKETPLACE_TYPE="xsoar"  # The default is "marketplace-dist"
else
  MARKETPLACE_TYPE=$1
fi
GCS_BUILD_BUCKET="marketplace-ci-build"
BUILD_BUCKET_PATH="content/builds/$CI_COMMIT_BRANCH/$CI_PIPELINE_ID/$MARKETPLACE_TYPE"
BUILD_BUCKET_PACKS_DIR_PATH="$BUILD_BUCKET_PATH/content/packs"
BUILD_BUCKET_FULL_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PATH"
BUILD_BUCKET_PACKS_DIR_FULL_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PACKS_DIR_PATH"
if [[ -z "$CREATE_DEPENDENCIES_ZIP" ]]; then
  CREATE_DEPENDENCIES_ZIP=false
fi
# ====== BUILD CONFIGURATION ======


CONTENT_PACKS_TO_UPLOAD_FILE="${ARTIFACTS_FOLDER_SERVER_TYPE}/content_packs_to_upload.json"

CONTENT_PACKS_TO_UPLOAD_JSON=$(cat "${CONTENT_PACKS_TO_UPLOAD_FILE}")
CONTENT_PACKS_TO_UPDATE_METADATA=$(echo "$CONTENT_PACKS_TO_UPLOAD_JSON" | jq -r '.packs_to_update_metadata | @csv')
if [ -z "${CONTENT_PACKS_TO_UPDATE_METADATA}" ]; then
  echo "Did not get content packs to update metadata in the bucket."
fi

CONTENT_PACKS_TO_UPLOAD=$(echo "$CONTENT_PACKS_TO_UPLOAD_JSON" | jq -r '.packs_to_upload | @csv')
if [[ -z "${CONTENT_PACKS_TO_UPLOAD}" ]]; then
  echo "Did not get content packs to update in the bucket."
fi

if [[ -z "${CONTENT_PACKS_TO_UPLOAD}" &&  -z "${CONTENT_PACKS_TO_UPDATE_METADATA}" ]]; then
  echo "Skipping upload step."
  exit 0
fi

echo "BUCKET_UPLOAD = $BUCKET_UPLOAD, FORCE_BUCKET_UPLOAD = $FORCE_BUCKET_UPLOAD, PACKS_TO_UPLOAD = $PACKS_TO_UPLOAD"
echo "Uploading the following content packs: ${CONTENT_PACKS_TO_UPLOAD}"
echo "Updating the following content packs (metadata changes): ${CONTENT_PACKS_TO_UPDATE_METADATA}"

# Workaround for the SDK hard-coded path.
mv "${ARTIFACTS_FOLDER}/markdown_images.json" "${ARTIFACTS_FOLDER_SERVER_TYPE}/markdown_images.json"

UPLOAD_SPECIFIC_PACKS=false
if [ -z "${BUCKET_UPLOAD}" ] && [ -z "${FORCE_BUCKET_UPLOAD}" ]; then
  # PR / nightly build
  python3 ./Tests/Marketplace/upload_packs.py -pa "${PACK_ARTIFACTS}" -d "${ARTIFACTS_FOLDER_SERVER_TYPE}/packs_dependencies.json" --artifacts-folder-server-type "${ARTIFACTS_FOLDER_SERVER_TYPE}" -e "$EXTRACT_FOLDER" -b $GCS_BUILD_BUCKET -s "$GCS_MARKET_KEY" -n "$CI_PIPELINE_ID" -pn "${CONTENT_PACKS_TO_UPLOAD_JSON}" -p $UPLOAD_SPECIFIC_PACKS -o false -sb "$BUILD_BUCKET_PACKS_DIR_PATH" -k "$PACK_SIGNING_KEY" -rt false -bu false -c "$CI_COMMIT_BRANCH" -f false -dz "$CREATE_DEPENDENCIES_ZIP" -mp "$MARKETPLACE_TYPE"
  echo "Finished updating content packs successfully."
else
  # upload-flow build - production / force / specific packs
  if [ -n "${PACKS_TO_UPLOAD}" ] && [ $FORCE_BUCKET_UPLOAD == "false" ]; then
    # In case there are given pack ids to upload and it is not a force
    echo "Upload the following specific packs: ${PACKS_TO_UPLOAD}"
    UPLOAD_SPECIFIC_PACKS=true
  fi
  python3 ./Tests/Marketplace/upload_packs.py -pa "${PACK_ARTIFACTS}" -d "${ARTIFACTS_FOLDER_SERVER_TYPE}/packs_dependencies.json" --artifacts-folder-server-type "${ARTIFACTS_FOLDER_SERVER_TYPE}" -e $EXTRACT_FOLDER -b $GCS_BUILD_BUCKET -s "$GCS_MARKET_KEY" -n $CI_PIPELINE_ID -pn "${CONTENT_PACKS_TO_UPLOAD_JSON}" -p $UPLOAD_SPECIFIC_PACKS -o $OVERRIDE_ALL_PACKS -sb $BUILD_BUCKET_PACKS_DIR_PATH -k $PACK_SIGNING_KEY -rt true -bu $BUCKET_UPLOAD -c $CI_COMMIT_BRANCH -f $FORCE_BUCKET_UPLOAD -dz "$CREATE_DEPENDENCIES_ZIP" -mp "$MARKETPLACE_TYPE"

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

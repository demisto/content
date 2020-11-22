#!/usr/bin/env bash

# exit on errors
set -e

CIRCLE_BRANCH=${CIRCLE_BRANCH:-unknown}
CIRCLE_BUILD_NUM=${CIRCLE_BUILD_NUM:-00000}
CIRCLE_ARTIFACTS=${CIRCLE_ARTIFACTS}
CIRCLE_SHA1=${CIRCLE_SHA1}
PACK_ARTIFACTS=$CIRCLE_ARTIFACTS/content_packs.zip
ID_SET=$CIRCLE_ARTIFACTS/id_set.json
EXTRACT_FOLDER=$(mktemp -d)
SECRET_CONF_PATH="./conf_secret.json"

if [[ -z "$GCS_MARKET_KEY" ]]; then
    echo "GCS_MARKET_KEY not set aborting!"
    exit 1
fi

echo "Preparing index file for testing ..."

KF=$(mktemp)
echo "$GCS_MARKET_KEY" > "$KF"
gcloud auth activate-service-account --key-file="$KF" > auth.out 2>&1
echo "Auth loaded successfully."

# ====== BUILD CONFIGURATION ======

GCS_BUILD_BUCKET="marketplace-ci-build"
BUILD_BUCKET_PATH="content/builds/$CIRCLE_BRANCH/$CIRCLE_BUILD_NUM"
TARGET_PATH="$BUILD_BUCKET_PATH/content/packs/index.zip"
INDEX_FULL_TARGET_PATH="$GCS_BUILD_BUCKET/$TARGET_PATH"
BUCKET_FULL_TARGET_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PATH"

# ====== PRODUCTION CONFIGURATION ======

GCS_MARKET_BUCKET="marketplace-dist"
INDEX_PATH="content/packs/index.zip"
LOCAL_INDEX_PATH="./index.zip"

# ====== TESTING CONFIGURATION ======

GCS_MARKET_TESTING_BUCKET="marketplace-dist-dev"
INDEX_TESTING_PATH="dev/content/packs/index.zip"
MASTER_HISTORY_PATH="master_history.txt"

if [ -f $LOCAL_INDEX_PATH ]; then
  echo "Removing file $LOCAL_INDEX_PATH"
  rm $LOCAL_INDEX_PATH
fi

echo "Copying master files at: gs://$GCS_MARKET_BUCKET/$INDEX_PATH to target path: $LOCAL_INDEX_PATH ..."
gsutil -m cp -r "gs://$GCS_MARKET_BUCKET/$INDEX_PATH" "$LOCAL_INDEX_PATH" > "$CIRCLE_ARTIFACTS/Validate Premium Packs.log" 2>&1
echo "Finished copying successfully."

touch $MASTER_HISTORY_PATH
git log master --pretty="%H" > $MASTER_HISTORY_PATH

echo "Master commit hash was $MASTER_COMMIT_HASH"

if [ ! -f $LOCAL_INDEX_PATH ]; then
  echo "Could not find file $LOCAL_INDEX_PATH"
  exit 1
else
  echo "Testing premium packs in against index file $LOCAL_INDEX_PATH"
  python3 ./Tests/scripts/validate_premium_packs.py --index_path "$LOCAL_INDEX_PATH" -s "$SECRET_CONF_PATH" --ami_env "$1" --master_history "$MASTER_HISTORY_PATH"
fi

rm $LOCAL_INDEX_PATH
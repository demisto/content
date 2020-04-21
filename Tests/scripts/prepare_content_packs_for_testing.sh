#!/usr/bin/env bash

# exit on errors
set -e

CIRCLE_BRANCH=${CIRCLE_BRANCH:-unknown}
CIRCLE_BUILD_NUM=${CIRCLE_BUILD_NUM:-00000}

if [[ -z "$GCS_MARKET_KEY" ]]; then
    echo "$GCS_MARKET_KEY not set aborting!"
    exit 1
fi

echo "Preparing content packs for testing ..."

KF=$(mktemp)
echo "$GCS_MARKET_KEY" > "$KF"
gcloud auth activate-service-account --key-file="$KF" > auth.out 2>&1
rm "$KF"
echo "Auth loaded successfully."

GCS_MARKET_BUCKET="marketplace-dist-dev"
SOURCE_PATH="content/packs"
TARGET_PATH="content/builds/$CIRCLE_BRANCH/$CIRCLE_BUILD_NUM"
echo "Copying master files at: $SOURCE_PATH to target path: $TARGET_PATH ..."
gsutil -m cp -r "gs://$GCS_MARKET_BUCKET/$SOURCE_PATH" "gs://$GCS_MARKET_BUCKET/$TARGET_PATH"
echo "Finished copying successfully."

echo "Updating modified content packs in the bucket ..."
CONTENT_PACKS_TO_INSTALL="./Tests/content_packs_to_install.txt"
while IFS= read -r line
do
  echo "$line" # search and install pack
done < "$CONTENT_PACKS_TO_INSTALL"
echo "Finished updating content packs successfully."

echo "Finished preparing content packs for testing successfully."

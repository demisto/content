#!/usr/bin/env bash

# exit on errors
set -e

CIRCLE_BRANCH=${CIRCLE_BRANCH:-unknown}
CIRCLE_BUILD_NUM=${CIRCLE_BUILD_NUM:-00000}
CIRCLE_ARTIFACTS=${CIRCLE_ARTIFACTS}
SECRET_CONF_PATH="./conf_secret.json"

GCS_MARKET_BUCKET="marketplace-dist"
INDEX_PATH="content/packs/index.zip"
LOCAL_INDEX_PATH="./index.zip"
MASTER_HISTORY_PATH="master_history.txt"

# ====== AUTHENTICATE =======

if [[ -z "$GCS_MARKET_KEY" ]]; then
    echo "GCS_MARKET_KEY not set aborting!"
    exit 1
fi

echo "Preparing index file for testing ..."

KF=$(mktemp)
echo "$GCS_MARKET_KEY" > "$KF"
gcloud auth activate-service-account --key-file="$KF" > auth.out 2>&1
echo "Auth loaded successfully."

# ====== DOWNLOAD INDEX ZIP ======

if [ -f $LOCAL_INDEX_PATH ]; then
  echo "Removing file $LOCAL_INDEX_PATH"
  rm $LOCAL_INDEX_PATH
fi

echo "Copying master files at: gs://$GCS_MARKET_BUCKET/$INDEX_PATH to target path: $LOCAL_INDEX_PATH ..."
gsutil -m cp -r "gs://$GCS_MARKET_BUCKET/$INDEX_PATH" "$LOCAL_INDEX_PATH" > "$CIRCLE_ARTIFACTS/Validate Premium Packs.log" 2>&1
echo "Finished copying successfully."

# ====== SAVE MASTER COMMIT HISTORY ======

touch $MASTER_HISTORY_PATH
git log master --pretty="%H" > $MASTER_HISTORY_PATH

# ====== RUN VALIDATIONS ======

if [ ! -f $LOCAL_INDEX_PATH ]; then
  echo "Could not find file $LOCAL_INDEX_PATH"
  exit 1
else
  echo "Testing premium packs in against index file $LOCAL_INDEX_PATH"
  python3 ./Tests/scripts/validate_premium_packs.py --index_path "$LOCAL_INDEX_PATH" -s "$SECRET_CONF_PATH" --ami_env "$1" --master_history "$MASTER_HISTORY_PATH"
fi

rm $LOCAL_INDEX_PATH

#!/usr/bin/env bash

# exit on errors
set -e

EXTRACT_FOLDER=$(mktemp -d)
BRANCH=${CI_COMMIT_BRANCH:-unknown}

SECRET_CONF_PATH="./conf_secret.json"

# ====== BUCKET CONFIGURATION ======

if [[ -z $STORAGE_BASE_PATH ]]; then
  if [[ $GCS_MARKET_BUCKET == $GCS_PRODUCTION_BUCKET ]]; then
   STORAGE_BASE_PATH="content"
  else
    STORAGE_BASE_PATH="upload-flow/builds/$CI_COMMIT_BRANCH/$CI_PIPELINE_ID/content"
  fi
fi
# ====== RUN VALIDATIONS ======

if [[ -n "$STORAGE_BASE_PATH" ]]; then
  echo "Validating index file in bucket at path gs://$GCS_MARKET_BUCKET/$STORAGE_BASE_PATH"
else
  echo "Validating index file in bucket at path gs://$GCS_MARKET_BUCKET/content/packs"
fi
python3 ./Tests/scripts/validate_index.py -sa "$GCS_MARKET_KEY" -e "$EXTRACT_FOLDER" -pb "$GCS_MARKET_BUCKET" -sb "$STORAGE_BASE_PATH/packs" -c "$BRANCH"

if [[ -n "$STORAGE_BASE_PATH" ]]; then
  echo "Validating premium packs in server against index file in bucket at path gs://$GCS_MARKET_BUCKET/$STORAGE_BASE_PATH."
else
  echo "Validating premium packs in server against index file in bucket at path gs://$GCS_MARKET_BUCKET/content/packs."
fi
python3 ./Tests/scripts/validate_premium_packs.py -sa "$GCS_MARKET_KEY" -e "$EXTRACT_FOLDER" -pb "$GCS_MARKET_BUCKET" -s "$SECRET_CONF_PATH" -a "$1" -sb "$STORAGE_BASE_PATH/packs"

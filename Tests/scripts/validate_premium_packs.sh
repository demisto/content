#!/usr/bin/env bash

# exit on errors
set -e

EXTRACT_FOLDER=$(mktemp -d)
BRANCH=${CI_COMMIT_BRANCH:-unknown}

SECRET_CONF_PATH="./conf_secret.json"

# ====== BUCKET CONFIGURATION ======

CREATE_INSTANCES_JOB_NUMBER=$(cat create_instances_build_num.txt)
if [[ $GCS_MARKET_BUCKET != "marketplace-dist" ]]; then
  STORAGE_BASE_PATH="upload-flow/builds/$BRANCH/$CREATE_INSTANCES_JOB_NUMBER/content/packs"
fi

# ====== RUN VALIDATIONS ======

if [[ -n "$STORAGE_BASE_PATH" ]]; then
  echo "Validating index file in bucket at path gs://$GCS_MARKET_BUCKET/$STORAGE_BASE_PATH"
else
  echo "Validating index file in bucket at path gs://$GCS_MARKET_BUCKET/content/packs"
fi
python3 ./Tests/scripts/validate_index.py -sa "$GCS_MARKET_KEY" -e "$EXTRACT_FOLDER" -pb "$GCS_MARKET_BUCKET" -sb "$STORAGE_BASE_PATH" -c "$BRANCH"

if [[ -n "$STORAGE_BASE_PATH" ]]; then
  echo "Validating premium packs in server against index file in bucket at path gs://$GCS_MARKET_BUCKET/$STORAGE_BASE_PATH."
else
  echo "Validating premium packs in server against index file in bucket at path gs://$GCS_MARKET_BUCKET/content/packs."
fi
python3 ./Tests/scripts/validate_premium_packs.py -sa "$GCS_MARKET_KEY" -e "$EXTRACT_FOLDER" -pb "$GCS_MARKET_BUCKET" -s "$SECRET_CONF_PATH" -a "$1" -sb "$STORAGE_BASE_PATH"

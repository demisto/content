#!/usr/bin/env bash

# exit on errors
set -e

EXTRACT_FOLDER=$(mktemp -d)
GCS_PATH=$(mktemp)
CIRCLE_BRANCH=${CIRCLE_BRANCH:-unknown}
echo $GCS_MARKET_KEY > $GCS_PATH

SECRET_CONF_PATH="./conf_secret.json"

# ====== RUN VALIDATIONS ======


if [[ -n "$STORAGE_BASE_PATH" ]]; then
  echo "Validating index file in bucket at path gs://$GCS_MARKET_BUCKET/$STORAGE_BASE_PATH"
else
  echo "Validating index file in bucket at path gs://$GCS_MARKET_BUCKET/content/packs"
fi
python3 ./Tests/scripts/validate_index.py -sa "$GCS_PATH" -e "$EXTRACT_FOLDER" -pb "$GCS_MARKET_BUCKET" -sb "$STORAGE_BASE_PATH"

if [[ -n "$STORAGE_BASE_PATH" ]]; then
  echo "Validating premium packs in server against index file in bucket at path gs://$GCS_MARKET_BUCKET/$STORAGE_BASE_PATH."
else
  echo "Validating premium packs in server against index file in bucket at path gs://$GCS_MARKET_BUCKET/content/packs."
fi
python3 ./Tests/scripts/validate_premium_packs.py -sa "$GCS_PATH" -e "$EXTRACT_FOLDER" -pb "$GCS_MARKET_BUCKET" -s "$SECRET_CONF_PATH" -a "$1" -sb "$STORAGE_BASE_PATH"

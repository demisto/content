#!/usr/bin/env bash

# exit on errors
set -e

EXTRACT_FOLDER=$(mktemp -d)
GCS_PATH=$(mktemp)
CIRCLE_BRANCH=${CIRCLE_BRANCH:-unknown}
echo $GCS_MARKET_KEY > $GCS_PATH

GCS_MARKET_BUCKET="marketplace-dist"

# ====== RUN VALIDATIONS ======

echo "Validating index file."
python3 ./Tests/scripts/validate_index.py -sa "$GCS_PATH" -e "$EXTRACT_FOLDER" -pb "$GCS_MARKET_BUCKET"

echo "Validating premium packs in server against index file."
python3 ./Tests/scripts/validate_premium_packs.py -sa "$GCS_PATH" -e "$EXTRACT_FOLDER" -pb "$GCS_MARKET_BUCKET" --secret "$SECRET_CONF_PATH" --ami_env "$1"
rm "$GCS_PATH"

#!/usr/bin/env bash

# exit on errors
set -e

EXTRACT_FOLDER=$(mktemp -d)
GCS_PATH=$(mktemp)
CIRCLE_BRANCH=${CIRCLE_BRANCH:-unknown}
echo $GCS_MARKET_KEY > $GCS_PATH

GCS_MARKET_BUCKET="marketplace-dist"
MASTER_HISTORY_PATH="master_history.txt"

# ====== SAVE MASTER COMMIT HISTORY ======

touch "$MASTER_HISTORY_PATH"
git log master --all --pretty="%H" > "$MASTER_HISTORY_PATH"

# ====== RUN VALIDATIONS ======

echo "Validating index file and testing premium packs in server"
python3 ./Tests/scripts/validate_premium_packs.py -sa "$GCS_PATH" -e "$EXTRACT_FOLDER" -pb "$GCS_MARKET_BUCKET" --secret "$SECRET_CONF_PATH" --ami_env "$1" --master_history "$MASTER_HISTORY_PATH"
rm "$GCS_PATH"


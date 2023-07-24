#!/usr/bin/env bash

echo "starting to install packs ..."

SECRET_CONF_PATH=$(cat secret_conf_path)
XSIAM_SERVERS_PATH=$(cat xsiam_servers_path)

EXTRACT_FOLDER=$(mktemp -d)

if [[ ! -f "$GCS_MARKET_KEY" ]]; then
    echo "GCS_MARKET_KEY not set aborting pack installation!"
    exit 1
fi

gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" > auth.out 2>&1
echo "Auth loaded successfully."

echo "starting configure_and_install_packs ..."

python3 ./Tests/Marketplace/configure_and_install_packs.py -s "$SECRET_CONF_PATH" --ami_env "$1" --branch "$CI_COMMIT_BRANCH" --build_number "$CI_PIPELINE_ID" --service_account $GCS_MARKET_KEY -e "$EXTRACT_FOLDER" --cloud_machine "$CLOUD_CHOSEN_MACHINE_ID" --cloud_servers_path $XSIAM_SERVERS_PATH --pack_ids_to_install "$ARTIFACTS_FOLDER/content_packs_to_install.txt" --cloud_servers_api_keys $XSIAM_API_KEYS
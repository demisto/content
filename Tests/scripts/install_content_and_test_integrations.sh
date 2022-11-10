#!/usr/bin/env bash

# exit on errors
set -e

SECRET_CONF_PATH=$(cat secret_conf_path)
XSIAM_SERVERS_PATH=$(cat xsiam_servers_path)
CONF_PATH="./Tests/conf.json"

IS_NIGHTLY=false

if [ -n "${NIGHTLY}" ]; then
  IS_NIGHTLY=true
fi

python3 ./Tests/configure_and_test_integration_instances.py -u "$USERNAME" -p "$PASSWORD" -c "$CONF_PATH" -s "$SECRET_CONF_PATH" --tests_to_run "$ARTIFACTS_FOLDER/filter_file.txt"  --pack_ids_to_install "$ARTIFACTS_FOLDER/content_packs_to_install.txt" -g "$GIT_SHA1" --ami_env "$1" -n $IS_NIGHTLY --branch "$CI_COMMIT_BRANCH" --build-number "$CI_PIPELINE_ID" -sa "$GCS_MARKET_KEY" --build_object_type "$2" --xsiam_machine "$XSIAM_CHOSEN_MACHINE_ID" --xsiam_servers_path $XSIAM_SERVERS_PATH --xsiam_servers_api_keys $XSIAM_API_KEYS
if [ -f ./Tests/test_pack.zip ]; then
  cp ./Tests/test_pack.zip "$ARTIFACTS_FOLDER"
fi

#!/usr/bin/env bash

# exit on errors
set -e

SECRET_CONF_PATH=$(cat secret_conf_path)
CONF_PATH="./Tests/conf.json"

IS_NIGHTLY=false

if [ -n "${NIGHTLY}" ]; then
  IS_NIGHTLY=true
fi

python3 ./Tests/configure_and_test_integration_instances.py -u "$USERNAME" -p "$PASSWORD" -c "$CONF_PATH" -s "$SECRET_CONF_PATH" --tests_to_run "$ARTIFACTS_FOLDER/filter_file.txt" -g "$GIT_SHA1" --ami_env "$1" -n $IS_NIGHTLY --branch "$CI_COMMIT_BRANCH" --build-number "$CI_PIPELINE_ID" -sa "$GCS_MARKET_KEY"
if [ -f ./Tests/test_pack.zip ]; then
  cp ./Tests/test_pack.zip "$ARTIFACTS_FOLDER"
fi

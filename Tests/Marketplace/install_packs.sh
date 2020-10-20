#!/usr/bin/env bash

echo "starting to install packs ..."

SECRET_CONF_PATH=$(cat secret_conf_path)
CONF_PATH="./Tests/conf.json"
DEMISTO_API_KEY=$(cat $SECRET_CONF_PATH | jq '.temp_apikey')


echo "starting configure_and_install_packs ..."
PREVIOUS_JOB_NUMBER=$(cat create_instances_build_num.txt)

python3 ./Tests/Marketplace/configure_and_install_packs.py -s "$SECRET_CONF_PATH" --ami_env "$1" --branch "$CIRCLE_BRANCH" --build-number "$PREVIOUS_JOB_NUMBER"

exit $RETVAL

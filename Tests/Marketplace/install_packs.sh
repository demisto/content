#!/usr/bin/env bash

echo "starting to install packs ..."

SECRET_CONF_PATH=$(cat secret_conf_path)

echo "starting configure_and_install_packs ..."
PREVIOUS_JOB_NUMBER=$(cat create_instances_build_num.txt)

python3 ./Tests/Marketplace/configure_and_install_packs.py -s "$SECRET_CONF_PATH" --ami_env "$1" --branch "$CIRCLE_BRANCH" --build_number "$PREVIOUS_JOB_NUMBER"

exit $RETVAL

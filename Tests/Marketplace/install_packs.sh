#!/usr/bin/env bash

echo "starting to install packs ..."

SECRET_CONF_PATH=$(cat secret_conf_path)

echo "starting configure_and_install_packs ..."

python3 ./Tests/Marketplace/configure_and_install_packs.py -s "$SECRET_CONF_PATH" --ami_env "$1" --branch "$CI_COMMIT_BRANCH" --build_number "$CI_PIPELINE_ID"

exit $RETVAL

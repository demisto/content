#!/usr/bin/env bash

echo "start slack notifier"

PRIVATE_CONF_PATH=$(cat private_conf_path)

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false

python ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -u $CIRCLE_BUILD_URL -b $CIRCLE_BUILD_NUM -i $CIRCLE_USERNAME -s $PRIVATE_CONF_PATH

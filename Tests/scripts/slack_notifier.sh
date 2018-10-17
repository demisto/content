#!/usr/bin/env bash

echo "start slack notifier"

USERNAME="admin"
PASSWORD=$(cat $SECRET_CONF_PATH | jq '.adminPassword')

SECRET_CONF_PATH=$(cat secret_conf_path)
[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false

python ./Tests/scripts/instance_notifier.py -n $IS_NIGHTLY -s "$SLACK_TOKEN" -c "$CIRCLECI_TOKEN" -e "$SECRET_CONF_PATH" -u "$USERNAME" -p "$PASSWORD"

echo "Finished slack notifier execution"

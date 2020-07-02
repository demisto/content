#!/usr/bin/env bash

echo "start instance test"

SECRET_CONF_PATH=$(cat secret_conf_path)

USERNAME=$(cat $SECRET_CONF_PATH | jq '.username')
PASSWORD=$(cat $SECRET_CONF_PATH | jq '.userPassword')

# remove quotes from password
temp="${PASSWORD%\"}"
temp="${temp#\"}"
PASSWORD=$temp

# remove quotes from username
temp="${USERNAME%\"}"
temp="${temp#\"}"
USERNAME=$temp

[ -n "${INSTANCE_TESTS}" ] && IS_INSTANCE_TESTS=true || IS_INSTANCE_TESTS=false

python3 ./Tests/instance_notifier.py -t $IS_INSTANCE_TESTS -s "$SLACK_TOKEN" -e "$SECRET_CONF_PATH" -u "$USERNAME" -p "$PASSWORD" -b "$CIRCLE_BUILD_URL" -n "$CIRCLE_BUILD_NUM"

echo "Finished slack notifier execution"

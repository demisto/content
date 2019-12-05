#!/usr/bin/env bash

echo "start instance test"

SECRET_CONF_PATH=$(cat secret_conf_path)
echo "secret conf path: $SECRET_CONF_PATH "

USERNAME=$(cat $SECRET_CONF_PATH | jq '.username')
PASSWORD=$(cat $SECRET_CONF_PATH | jq '.userPassword')

echo "username: $USERNAME"
echo "password: $PASSWORD"

# remove quotes from password
temp="${PASSWORD%\"}"
temp="${temp#\"}"
echo "temp: $temp"
PASSWORD=$temp

# remove quotes from username
temp="${USERNAME%\"}"
temp="${temp#\"}"
USERNAME=$temp

[ -n "${INSTANCE_TESTS}" ] && IS_INSTANCE_TESTS=true || IS_INSTANCE_TESTS=false

python ./Tests/instance_notifier.py -n IS_INSTANCE_TESTS -s "$SLACK_TOKEN" -e "$SECRET_CONF_PATH" -u "$USERNAME" -p "$PASSWORD" -b "$CIRCLE_BUILD_URL"

echo "Finished slack notifier execution"

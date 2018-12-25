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

SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false

python ./Tests/instance_notifier.py -n $IS_NIGHTLY -s "$SLACK_TOKEN" -e "$SECRET_CONF_PATH" -u "$USERNAME" -p "$PASSWORD" -c "$SERVER_URL"

echo "Finished slack notifier execution"

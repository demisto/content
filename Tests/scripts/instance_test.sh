#!/usr/bin/env bash

echo "start instance test"

USERNAME="admin"
PASSWORD=$(cat $SECRET_CONF_PATH | jq '.adminNewPassword')

# remove quotes from password
temp="${PASSWORD%\"}"
temp="${temp#\"}"
PASSWORD=$temp

SECRET_CONF_PATH=$(cat secret_conf_path)
[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false

SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"

python ./Tests/instance_notifier.py -n $IS_NIGHTLY -s "$SLACK_TOKEN" -e "$SECRET_CONF_PATH" -u "$USERNAME" -p "$PASSWORD" -c "$SERVER_URL"

echo "Finished slack notifier execution"
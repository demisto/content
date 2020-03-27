#!/usr/bin/env bash

echo "start content tests"

SECRET_CONF_PATH=$(cat secret_conf_path)
CONF_PATH="./Tests/conf.json"
<<<<<<< HEAD
USERNAME=$(cat $SECRET_CONF_PATH | jq '.username')

# remove quotes from username
temp="${USERNAME%\"}"
temp="${temp#\"}"
USERNAME=$temp
=======
DEMISTO_API_KEY=$(cat $SECRET_CONF_PATH | jq '.temp_apikey')

temp="${DEMISTO_API_KEY%\"}"
temp="${temp#\"}"
DEMISTO_API_KEY=$temp
>>>>>>> upstream/master

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false

echo "Starts tests with server url - $SERVER_URL"
<<<<<<< HEAD
python ./Tests/test_content.py -u "$USERNAME" -p "$USERNAME" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CIRCLE_BUILD_NUM" -g "$CIRCLE_BRANCH"
=======
python ./Tests/test_content.py -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CIRCLE_BUILD_NUM" -g "$CIRCLE_BRANCH"
>>>>>>> upstream/master

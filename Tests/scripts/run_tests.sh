#!/usr/bin/env bash

echo "start content tests"

SECRET_CONF_PATH=$(cat secret_conf_path)
SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"
CONF_PATH="./Tests/conf.json"
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

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false

code_1=0
if [[ "$CIRCLE_BRANCH" == "master" ]] && ! $IS_NIGHTLY; then
  python ./Tests/configure_and_test_integration_instances.py -u "$USERNAME" -p "$PASSWORD" -c "$CONF_PATH" -s "$SECRET_CONF_PATH" -g "$GIT_SHA1" --ami_env "$1"
  code_1=$?
fi

python ./Tests/test_content.py -u "$USERNAME" -p "$PASSWORD" -s "$SERVER_URL" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CIRCLE_BUILD_NUM" -g "$CIRCLE_BRANCH" -m "$MEM_CHECK" --isAMI true -d "$1"

code_2=$?
let "exit_code = $code_1 + $code_2"

exit $exit_code

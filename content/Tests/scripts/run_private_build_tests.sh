#!/usr/bin/env bash

echo "start content tests"

SECRET_CONF_PATH=$(cat secret_conf_path)
CONF_PATH="./Tests/conf.json"
DEMISTO_API_KEY=$(cat $SECRET_CONF_PATH | jq -r '.temp_apikey')

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false

code_1=0
code_2=0

echo "starting configure_and_test_integration_instances"

python3 ./Tests/private_build/configure_and_test_integration_instances_private.py -u "$USERNAME" -p "$PASSWORD" -c "$CONF_PATH" -s "$SECRET_CONF_PATH" -g "$GIT_SHA1" --ami_env "$1" -n $IS_NIGHTLY --branch "$BRANCH_NAME" --build-number "$GITHUB_RUN_NUMBER" -pr true --test_pack_path '/home/runner/work/content-private/content-private/content/artifacts/packs'
code_1=$?


if [ $code_1 -ne 1 ] ; then
  if [ -n "${NON_AMI_RUN}" ]; then
    # non AMI
    python3 ./Tests/private_build/run_content_tests_private.py -sa "$GCS_PATH" -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$GITHUB_RUN_NUMBER" -g "$BRANCH_NAME" -m "$MEM_CHECK" -d "$1"
  else
    # AMI
    python3 ./Tests/private_build/run_content_tests_private.py -sa "$GCS_PATH" -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$GITHUB_RUN_NUMBER" -g "$BRANCH_NAME" -m "$MEM_CHECK" --isAMI true -d "$1"
  fi
fi

code_2=$?

if [ $code_1 -eq 0 ] && [ $code_2 -eq 0 ] ; then
  role="$(echo -e "${INSTANCE_ROLE}" | tr -d '[:space:]')"
  filepath="./Tests/is_build_passed_${role}.txt"
  touch "$filepath"
fi
let "exit_code = $code_1 + $code_2"

exit $exit_code

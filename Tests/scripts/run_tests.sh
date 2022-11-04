#!/usr/bin/env bash

SECRET_CONF_PATH=$(cat secret_conf_path)
XSIAM_SERVERS_PATH=$(cat xsiam_servers_path)
CONF_PATH="./Tests/conf.json"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false
[ -z "${NON_AMI_RUN}" ] && IS_AMI_RUN=true || IS_AMI_RUN=false

echo "export GOOGLE_APPLICATION_CREDENTIALS=$GCS_ARTIFACTS_KEY" >> $BASH_ENV
source $BASH_ENV

demisto-sdk test-content -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CI_BUILD_ID" -g "$CI_COMMIT_BRANCH" -m "$MEM_CHECK" --is-ami $IS_AMI_RUN -d "$1" --xsiam-machine "$XSIAM_CHOSEN_MACHINE_ID" --xsiam-servers-path $XSIAM_SERVERS_PATH --server-type "$SERVER_TYPE" --use-retries --xsiam-servers-api-keys-path $XSIAM_API_KEYS

RETVAL=$?

if [ $RETVAL -eq 0 ]; then
  role="$(echo -e "$1" | tr -d '[:space:]')"
  filepath="./Tests/is_build_passed_${role}.txt"
  touch "$filepath"
fi

exit $RETVAL

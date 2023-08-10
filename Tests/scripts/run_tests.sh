#!/usr/bin/env bash

SECRET_CONF_PATH=$(cat secret_conf_path)
CLOUD_SERVERS_PATH=$(cat $CLOUD_SERVERS_FILE)
echo ${CLOUD_API_KEYS} > "cloud_api_keys.json"
CONF_PATH="./Tests/conf.json"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false
[ -z "${NON_AMI_RUN}" ] && IS_AMI_RUN=true || IS_AMI_RUN=false

echo "export GOOGLE_APPLICATION_CREDENTIALS=$GCS_ARTIFACTS_KEY" >> $BASH_ENV
source $BASH_ENV

demisto-sdk test-content -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CI_BUILD_ID" -g "$CI_COMMIT_BRANCH" -m "$MEM_CHECK" --is-ami $IS_AMI_RUN -d "$1" --xsiam-machine "$CLOUD_CHOSEN_MACHINE_ID" --xsiam-servers-path "$CLOUD_SERVERS_PATH" --server-type "$SERVER_TYPE" --use-retries --xsiam-servers-api-keys-path "cloud_api_keys.json"

RETVAL=$?

if [ $RETVAL -eq 0 ]; then
  role="$(echo -e "$1" | tr -d '[:space:]')"
  echo $role
  filepath="$ARTIFACTS_FOLDER/is_build_passed_${role}.txt"
  touch "$filepath"
fi

if [ "${IS_NIGHTLY}" = true ]; then
  exit 0
fi

exit $RETVAL
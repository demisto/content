#!/usr/bin/env bash

SECRET_CONF_PATH=$(cat secret_conf_path)
CLOUD_SERVERS_PATH=$(cat "${CLOUD_SERVERS_FILE}")
echo "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
CONF_PATH="./Tests/conf.json"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false
[ -z "${NON_AMI_RUN}" ] && IS_AMI_RUN=true || IS_AMI_RUN=false

echo "export GOOGLE_APPLICATION_CREDENTIALS=$GCS_ARTIFACTS_KEY" >> "${BASH_ENV}"
source "${BASH_ENV}"

echo "Running server tests on role: $1 is nightly: ${IS_NIGHTLY} is AMI run: ${IS_AMI_RUN} mem check: ${MEM_CHECK}"

RETVAL=0
if [ -n "${CLOUD_CHOSEN_MACHINE_IDS}" ]; then
  IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
  for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
    demisto-sdk test-content -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CI_BUILD_ID" -g "$CI_COMMIT_BRANCH" -m "$MEM_CHECK" --is-ami $IS_AMI_RUN -d "$1" --xsiam-machine "${CLOUD_CHOSEN_MACHINE_ID}" --xsiam-servers-path "$CLOUD_SERVERS_PATH" --server-type "$SERVER_TYPE" --use-retries --xsiam-servers-api-keys-path "cloud_api_keys.json"
    if [ $? -ne 0 ]; then
      RETVAL=1
      echo "Failed to test content on cloud machine:${CLOUD_CHOSEN_MACHINE_ID}"
    fi
  done
fi

if [ "${RETVAL}" -eq 0 ]; then
  role="$(echo -e "$1" | tr -d '[:space:]')"
  filepath="$ARTIFACTS_FOLDER/is_build_passed_${role}.txt"
  echo "Build passed for role: $1 writing it passed to artifacts folder in file: ${filepath}"
  touch "${filepath}"
fi

if [[ "${IS_NIGHTLY}" == "true" ]]; then
  echo "Finish running server tests on role: $1 it's the nightly build, exiting with code 0"
  exit 0
fi

echo "Finish running server tests on role: $1, exiting with code ${RETVAL}"
exit "${RETVAL}"

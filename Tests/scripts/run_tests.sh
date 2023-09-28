#!/usr/bin/env bash

MODELING_RULES_RESULTS_FILE_NAME="${ARTIFACTS_FOLDER_INSTANCE}/test_playbooks_report.xml"

function write_empty_test_results_file() {
  cat <<EOF > "${MODELING_RULES_RESULTS_FILE_NAME}"
<?xml version='1.0' encoding='utf-8'?>
<testsuites />
EOF
}

# Parsing the user inputs.
generate_empty_results_file="false"
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --generate-empty-result-file) generate_empty_results_file="true"
      shift;;
    *)  # unknown option.
      shift;;
  esac
done

if [[ "${generate_empty_results_file,,}" == "true" ]]; then
  write_empty_test_results_file
  exit 0
fi

SECRET_CONF_PATH=$(cat secret_conf_path)
if [ -n "${CLOUD_SERVERS_FILE}" ]; then
  CLOUD_SERVERS_PATH=$(cat "${CLOUD_SERVERS_FILE}")
  echo "CLOUD_SERVERS_PATH is set to: ${CLOUD_SERVERS_PATH}"
fi
if [ -n "${CLOUD_API_KEYS}" ]; then
  echo "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
fi

CONF_PATH="./Tests/conf.json"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false
[ -z "${NON_AMI_RUN}" ] && IS_AMI_RUN=true || IS_AMI_RUN=false

echo "export GOOGLE_APPLICATION_CREDENTIALS=$GCS_ARTIFACTS_KEY" >> "${BASH_ENV}"
source "${BASH_ENV}"

echo "Running server tests on Instance role:${INSTANCE_ROLE}, nightly:${IS_NIGHTLY}, AMI run:${IS_AMI_RUN} mem check:${MEM_CHECK} ARTIFACTS_FOLDER:${ARTIFACTS_FOLDER}"
echo "${INSTANCE_ROLE}" > "${ARTIFACTS_FOLDER_INSTANCE}/instance_role.txt"
echo "${INSTANCE_ROLE}" >> "${ARTIFACTS_FOLDER}/${SERVER_TYPE}_test_playbooks_roles.txt"
echo "${ARTIFACTS_FOLDER_INSTANCE}" >> "${ARTIFACTS_FOLDER}/${SERVER_TYPE}_test_playbooks_artifacts_directories.txt"

exit_code=0
if [[ "${INSTANCE_ROLE}" == "XSIAM" ]]; then
  if [ -n "${CLOUD_CHOSEN_MACHINE_IDS}" ]; then
    IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
    for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
      demisto-sdk test-content -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n "${IS_NIGHTLY}" -t "$SLACK_TOKEN" \
        -a "$CIRCLECI_TOKEN" -b "$CI_BUILD_ID" -g "$CI_COMMIT_BRANCH" -m "${MEM_CHECK}" --is-ami "${IS_AMI_RUN}" -d "${INSTANCE_ROLE}" \
        --xsiam-machine "${CLOUD_CHOSEN_MACHINE_ID}" --xsiam-servers-path "$CLOUD_SERVERS_PATH" --server-type "$SERVER_TYPE" \
        --use-retries --xsiam-servers-api-keys-path "cloud_api_keys.json" --artifacts_path "${ARTIFACTS_FOLDER_INSTANCE}"
      command_exit_code=$?
      if [ "${command_exit_code}" -ne 0 ]; then
        exit_code=1
        echo "Failed to run test content on cloud machine:${CLOUD_CHOSEN_MACHINE_ID} with exit code:${command_exit_code}"
      fi
    done
  else
    echo "No cloud machines were chosen to run tests on"
    exit_code=1
  fi
else
    demisto-sdk test-content -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n "${IS_NIGHTLY}" -t "$SLACK_TOKEN" \
      -a "$CIRCLECI_TOKEN" -b "$CI_BUILD_ID" -g "$CI_COMMIT_BRANCH" -m "${MEM_CHECK}" --is-ami "${IS_AMI_RUN}" -d "${INSTANCE_ROLE}" \
      --xsiam-machine "${CLOUD_CHOSEN_MACHINE_ID}" --xsiam-servers-path "$CLOUD_SERVERS_PATH" --server-type "$SERVER_TYPE" \
      --use-retries --xsiam-servers-api-keys-path "cloud_api_keys.json" --artifacts_path "${ARTIFACTS_FOLDER_INSTANCE}"
    exit_code=$?
    echo "Failed to run test content with exit code:${exit_code}"
fi

if [ "${exit_code}" -eq 0 ]; then
  role="$(echo -e "${INSTANCE_ROLE}" | tr -d '[:space:]')"
  filepath="${ARTIFACTS_FOLDER}/is_build_passed_${role}.txt"
  echo "Build passed for role: ${INSTANCE_ROLE} writing it passed to artifacts folder in file: ${filepath}"
  touch "${filepath}"
else
  echo "Build failed for role: ${INSTANCE_ROLE} with exit code: ${exit_code}"
fi

if [[ "${IS_NIGHTLY}" == "true" ]]; then
  echo "Finish running server tests on role: ${INSTANCE_ROLE} it's the nightly build, exiting with code 0"
  exit 0
fi

echo "Finish running server tests on role: ${INSTANCE_ROLE}, exiting with code ${exit_code}"
exit "${exit_code}"

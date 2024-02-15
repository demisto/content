#!/usr/bin/env bash

TEST_PLAYBOOKS_RESULTS_FILE_NAME="${ARTIFACTS_FOLDER_INSTANCE}/test_playbooks_report.xml"

function write_empty_test_results_file() {
  cat <<EOF > "${TEST_PLAYBOOKS_RESULTS_FILE_NAME}"
<?xml version='1.0' encoding='utf-8'?>
<testsuites />
EOF
}

# Parsing the user inputs.
generate_empty_results_file="false"
while [[ "$#" -gt 0 ]]; do
  case "${1}" in
    --generate-empty-result-file) generate_empty_results_file="true"
      shift;;
    *)  # unknown option.
      shift
      echo "Unknown option was received: $1"
      ;;
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
  cat "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
fi

CONF_PATH="./Tests/conf.json"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false
[ -z "${NON_AMI_RUN}" ] && IS_AMI_RUN=true || IS_AMI_RUN=false

echo "export GOOGLE_APPLICATION_CREDENTIALS=$GCS_ARTIFACTS_KEY" >> "${BASH_ENV}"
source "${BASH_ENV}"

echo "Running server tests on Instance role:${INSTANCE_ROLE}, nightly:${IS_NIGHTLY}, AMI run:${IS_AMI_RUN} mem check:${MEM_CHECK} ARTIFACTS_FOLDER:${ARTIFACTS_FOLDER}"

exit_code=0
if [[ "${SERVER_TYPE}" == "XSIAM" ]]; then

  if [ -n "${CLOUD_CHOSEN_MACHINE_IDS}" ]; then
    IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
    for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
      demisto-sdk test-content -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n "${IS_NIGHTLY}" -t "$SLACK_TOKEN" \
        -a "$CIRCLECI_TOKEN" -b "${CI_PIPELINE_ID}" -g "$CI_COMMIT_BRANCH" -m "${MEM_CHECK}" --is-ami "${IS_AMI_RUN}" -d "${INSTANCE_ROLE}" \
        --xsiam-machine "${CLOUD_CHOSEN_MACHINE_ID}" --xsiam-servers-path "$CLOUD_SERVERS_PATH" --server-type "${SERVER_TYPE}" \
        --use-retries --xsiam-servers-api-keys-path "cloud_api_keys.json" --artifacts-path="${ARTIFACTS_FOLDER_INSTANCE}" --product-type="${PRODUCT_TYPE}"
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

# elif [[ "${SERVER_TYPE}" == "XSOAR" ]]; then
elif [[ "${SERVER_TYPE}" == "XSOAR" ]] || [[ "${SERVER_TYPE}" == "XSOAR SAAS" ]]; then
    echo "$CLOUD_SERVERS_PATH"
    demisto-sdk test-content -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n "${IS_NIGHTLY}" -t "$SLACK_TOKEN" \
      -a "$CIRCLECI_TOKEN" -b "${CI_PIPELINE_ID}" -g "$CI_COMMIT_BRANCH" -m "${MEM_CHECK}" --is-ami "${IS_AMI_RUN}" -d "${INSTANCE_ROLE}" \
      --xsiam-machine "test_opp" --xsiam-servers-path "$CLOUD_SERVERS_PATH" --server-type "XSOAR SAAS" \
      --use-retries --xsiam-servers-api-keys-path "cloud_api_keys.json" --artifacts-path="${ARTIFACTS_FOLDER_INSTANCE}" --product-type="${PRODUCT_TYPE}"
    exit_code=$?
    echo "Failed to run test content with exit code:${exit_code}"
else
  exit_on_error 1 "Unknown server type: ${SERVER_TYPE}"
fi

if [ "${exit_code}" -eq 0 ]; then
  role="$(echo -e "${INSTANCE_ROLE}" | tr -d '[:space:]')"
  filepath="${ARTIFACTS_FOLDER}/is_build_passed_${role}.txt"
  echo "Build passed for instance role: ${INSTANCE_ROLE}, server type:${SERVER_TYPE} writing it passed to artifacts folder in file: ${filepath}"
  touch "${filepath}"
else
  echo "Build failed for instance role: ${INSTANCE_ROLE}, server type:${SERVER_TYPE} with exit code: ${exit_code}"
fi

if [ -n "${FAIL_ON_ERROR}" ]; then
  if [ "${exit_code}" -eq 0 ]; then
    echo "Finish running server tests on instance role: ${INSTANCE_ROLE}, server type:${SERVER_TYPE} - exiting with code 0"
    exit 0
  else
    echo "Finish running server tests with errors on instance role: ${INSTANCE_ROLE}, server type:${SERVER_TYPE} - exiting with code 1"
    exit 1 
  fi 
else
  echo "Finish running server tests on instance role: ${INSTANCE_ROLE}, server type:${SERVER_TYPE} - Error handling will be done on the results job, exiting with code 0"
  exit 0
fi


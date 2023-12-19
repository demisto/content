#!/usr/bin/env bash

function exit_on_error {
    if [ "${1}" -ne 0 ]; then
        echo "ERROR: ${2}, exiting with code ${1}" 1>&2
        exit "${1}"
    fi
}

MODELING_RULES_RESULTS_FILE_NAME="${ARTIFACTS_FOLDER_INSTANCE}/test_modeling_rules_report.xml"

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

if [[ ! -s "${ARTIFACTS_FOLDER_SERVER_TYPE}/modeling_rules_to_test.txt" ]]; then
  echo "No modeling rules were marked for testing during test collection - writing empty junit file to ${MODELING_RULES_RESULTS_FILE_NAME}"
  write_empty_test_results_file
  exit 0
fi

echo "Found modeling rules to test, starting test modeling rules"

CURRENT_DIR=$(pwd)
echo "CURRENT_DIR: ${CURRENT_DIR}"
echo "NIGHTLY: ${NIGHTLY}"

MODELING_RULES_ARRAY=($(cat "${ARTIFACTS_FOLDER_SERVER_TYPE}/modeling_rules_to_test.txt"))

echo "MODELING_RULES_ARRAY size:${#MODELING_RULES_ARRAY[@]}"
count=0
for modeling_rule in "${MODELING_RULES_ARRAY[@]}"; do
  MODELING_RULE_TEST_FILE_PATTERN="${CURRENT_DIR}/Packs/${modeling_rule}/*_testdata.json"
  # If it is nightly, run `test modeling rules` only on modeling rules that have `_testdata.json` file.
  # globbing is needed here, don't quote the variable.
  # shellcheck disable=SC2086
  if [ -z "${NIGHTLY}" ] || [ -e ${MODELING_RULE_TEST_FILE_PATTERN} ]; then
    count=$((count+1))
    if [[ -n "${MODELING_RULES_TO_TEST}" ]]; then
        MODELING_RULES_TO_TEST="${MODELING_RULES_TO_TEST} Packs/${modeling_rule}"
    else
        MODELING_RULES_TO_TEST="Packs/${modeling_rule}"
    fi
  fi
done

echo "Found ${count} modeling rules to test out of ${#MODELING_RULES_ARRAY[@]} modeling rules"

if [[ -z "${MODELING_RULES_TO_TEST}" ]]; then
    exit_on_error 1 "There was a problem reading the list of modeling rules that require testing from '${ARTIFACTS_FOLDER_SERVER_TYPE}/modeling_rules_to_test.txt'"
fi

if [ -n "${CLOUD_API_KEYS}" ]; then
  if [ "${TEST_XDR_ENV}" == "true" ]; then
    cat "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
  else
    echo "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
  fi
else
  exit_on_error 1 "CLOUD_API_KEYS is empty"
fi

if [ -n "${CLOUD_API_TOKENS}" ]; then
  if [ "${TEST_XDR_ENV}" == "true" ]; then
    cat "${CLOUD_API_TOKENS}" > "cloud_api_tokens.json"
  else
    echo "${CLOUD_API_TOKENS}" > "cloud_api_tokens.json"
  fi
else
  exit_on_error 1 "CLOUD_API_TOKENS is empty"
fi

if [ -n "${CLOUD_CHOSEN_MACHINE_IDS}" ]; then

  XSIAM_SERVERS_PATH=${XSIAM_SERVERS_PATH:-"xsiam_servers.json"}
  echo "Testing Modeling Rules - Results will be saved to ${MODELING_RULES_RESULTS_FILE_NAME}"

  IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
  exit_code=0
  for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do

    # Get XSIAM Tenant Config Details
    XSIAM_SERVER_CONFIG=$(jq -r ".[\"${CLOUD_CHOSEN_MACHINE_ID}\"]" < "${XSIAM_SERVERS_PATH}")
    XSIAM_URL=$(echo "${XSIAM_SERVER_CONFIG}" | jq -r ".[\"base_url\"]")
    AUTH_ID=$(echo "${XSIAM_SERVER_CONFIG}" | jq -r ".[\"x-xdr-auth-id\"]")
    API_KEY=$(jq -r ".[\"${CLOUD_CHOSEN_MACHINE_ID}\"]" < "cloud_api_keys.json")
    XSIAM_TOKEN=$(jq -r ".[\"${CLOUD_CHOSEN_MACHINE_ID}\"]" < "cloud_api_tokens.json")

    # shellcheck disable=SC2086
    demisto-sdk modeling-rules test --xsiam-url="${XSIAM_URL}" --auth-id="${AUTH_ID}" --api-key="${API_KEY}" \
      --xsiam-token="${XSIAM_TOKEN}" --non-interactive --junit-path="${MODELING_RULES_RESULTS_FILE_NAME}" \
      ${MODELING_RULES_TO_TEST}
    command_exit_code=$?
    if [ "${command_exit_code}" -ne 0 ]; then
      echo "Failed testing Modeling Rules on machine ${CLOUD_CHOSEN_MACHINE_ID} with exit code:${command_exit_code}"
      exit_code=1
    fi
  done
  if [ "${exit_code}" -eq 0 ]; then
    echo "Successfully tested Modeling Rules on all chosen machines"
  else
    echo "Failed testing Modeling Rules on at least one of the chosen machines"
  fi

  echo "Finish running test modeling rules, error handling will be done on the results job, exiting with code 0"
  exit 0

else
  write_empty_test_results_file
  exit_on_error 1 "No machines were chosen"
fi

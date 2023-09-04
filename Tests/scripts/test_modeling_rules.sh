#!/bin/bash
set -e

MODELING_RULES_RESULTS_FILE_NAME="${ARTIFACTS_FOLDER}/modeling_rules_results.xml"

if [[ ! -s "${ARTIFACTS_FOLDER}/modeling_rules_to_test.txt" ]]; then
  echo "No modeling rules were marked for testing during test collection - writing empty junit file to ${MODELING_RULES_RESULTS_FILE_NAME}"
  cat <<EOF > "${MODELING_RULES_RESULTS_FILE_NAME}"
<?xml version='1.0' encoding='utf-8'?>
<testsuites />
EOF
  exit 0
fi

XSIAM_SERVERS_PATH=${XSIAM_SERVERS_PATH:-"xsiam_servers.json"}

# Get XSIAM Tenant Config Details
XSIAM_SERVER_CONFIG=$(jq -r ".[\"$CLOUD_CHOSEN_MACHINE_ID\"]" < "$XSIAM_SERVERS_PATH")
XSIAM_URL=$(echo "$XSIAM_SERVER_CONFIG" | jq -r ".[\"base_url\"]")
AUTH_ID=$(echo "$XSIAM_SERVER_CONFIG" | jq -r ".[\"x-xdr-auth-id\"]")
API_KEY=$(jq -r ".[\"$CLOUD_CHOSEN_MACHINE_ID\"]" < "$XSIAM_API_KEYS")
XSIAM_TOKEN=$(jq -r ".[\"$CLOUD_CHOSEN_MACHINE_ID\"]" < "$XSIAM_TOKENS")
CURRENT_DIR=$(pwd)

MODELING_RULES_ARRAY=($(cat "${ARTIFACTS_FOLDER}/modeling_rules_to_test.txt"))
for modeling_rule in "${MODELING_RULES_ARRAY[@]}"; do
  MODELING_RULE_TEST_FILE_PATTERN="$CURRENT_DIR/Packs/$modeling_rule/*_testdata.json"
  # If it is nightly, run `test modeling rules` only on modeling rules that have `_testdata.json` file.
  if [ -z "$NIGHTLY" ] || [ -e $MODELING_RULE_TEST_FILE_PATTERN ]; then
    if [[ -n "$MODELING_RULES_TO_TEST" ]]; then
        MODELING_RULES_TO_TEST="$MODELING_RULES_TO_TEST Packs/$modeling_rule"
    else
        MODELING_RULES_TO_TEST="Packs/$modeling_rule"
    fi
  fi
done

if [[ -z "${MODELING_RULES_TO_TEST}" ]]; then
    echo "There was a problem reading the list of modeling rules that require testing from '${ARTIFACTS_FOLDER}/modeling_rules_to_test.txt'"
    exit 1
fi

MODELING_RULES_RESULTS_FILE_NAME="${ARTIFACTS_FOLDER}/modeling_rules_results.xml"
if DEMISTO_SDK_SKIP_VERSION_CHECK=True demisto-sdk modeling-rules test --help 2>&1 | grep -q 'junit-path'; then
  MODELING_RULES_RESULTS_ARG=(--junit-path="${MODELING_RULES_RESULTS_FILE_NAME}")
  echo "Testing Modeling Rules - Results will be saved to ${MODELING_RULES_RESULTS_FILE_NAME}"
else
  echo "Testing Modeling Rules - demisto-sdk version is too old, creating empty junit file to ${MODELING_RULES_RESULTS_FILE_NAME}"
  MODELING_RULES_RESULTS_ARG=()
  cat <<EOF > "${MODELING_RULES_RESULTS_FILE_NAME}"
<?xml version='1.0' encoding='utf-8'?>
<testsuites />
EOF
    MODELING_RULES_RESULTS_FILE_NAME=""  # Reset the file name so that the next command will not try to use it.
fi

demisto-sdk modeling-rules test --xsiam-url="$XSIAM_URL" --auth-id="$AUTH_ID" --api-key="$API_KEY" \
  --xsiam-token="$XSIAM_TOKEN" --non-interactive "${MODELING_RULES_RESULTS_ARG[@]}" \
  ${MODELING_RULES_TO_TEST}
exit_code=$?
echo "Finished testing Modeling Rules, exit_code=$exit_code"

if [[ "${exit_code}" -ne 0 ]]; then
  echo "Failed to test modeling rules"
  if [ -n "${NIGHTLY}" ] && [ -n "${MODELING_RULES_RESULTS_FILE_NAME}" ]; then
    echo "This is a nightly build, converting the results to Jira issues and exiting with 0"
    python3 "${CURRENT_DIR}/Tests/scripts/convert_test_result_to_jira_issues.py" --junit-path "${MODELING_RULES_RESULTS_FILE_NAME}"
    exit_code=$?
    if [[ "${exit_code}" -ne 0 ]]; then
      echo "Failed to convert the results to Jira issues"
      exit ${exit_code}
    fi
    exit 0  # Exiting with 0 so that the build will not fail, because we successfully converted the results to Jira issues.
  else
    exit ${exit_code}
  fi
fi

exit ${exit_code}

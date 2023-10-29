#!/usr/bin/env bash

function exit_on_error {
    if [ "${1}" -ne 0 ]; then
        echo "ERROR: ${2}, exiting with code ${1}" 1>&2
        exit "${1}"
    fi
}

echo "Starting the print test modeling rule summary script - Server type: ${SERVER_TYPE}, Product type: ${PRODUCT_TYPE}"

python3 ./Tests/Marketplace/print_test_modeling_rule_summary.py --artifacts-path "${ARTIFACTS_FOLDER}"
summary_exit_code=$?

if [ -n "${NIGHTLY}" ]; then
  if [ "${TEST_MODELING_RULE_JIRA_TICKETS,,}" == "true" ]; then
    echo "This is a nightly build, converting the results to Jira issues and exiting with 0"
    python3 ./Tests/scripts/convert_test_modeling_result_to_jira_issues.py --artifacts-path "${ARTIFACTS_FOLDER}" --build-number "${CI_PIPELINE_ID}"
    exit_on_error $? "Failed to convert the Test modeling rule results to Jira issues"

    echo "Finished converting the Test modeling rule results to Jira issues, exiting with 0"
    exit 0  # Exiting with 0 so that the build will not fail, because we successfully converted the results to Jira issues.
  else
    echo "This is a nightly build, but TEST_MODELING_RULE_JIRA_TICKETS is not set to true"
    echo "Exiting with the print summary exit code:${summary_exit_code}"
    exit "${summary_exit_code}"
  fi
else
  echo "This is not a nightly build, Exiting with the print summary exit code:${summary_exit_code}"
  exit "${summary_exit_code}"
fi

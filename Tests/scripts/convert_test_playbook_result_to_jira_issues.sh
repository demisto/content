#!/usr/bin/env bash

function exit_on_error {
    if [ "${1}" -ne 0 ]; then
        echo "ERROR: ${2}, exiting with code ${1}" 1>&2
        exit "${1}"
    fi
}

python3 ./Tests/Marketplace/print_test_playbook_summary.py --failed_tests_path "${ARTIFACTS_FOLDER_INSTANCE}/failed_tests.txt" --succeeded_tests_path "${ARTIFACTS_FOLDER_INSTANCE}/succeeded_tests.txt"
summary_exit_code=$?

if [ -n "${NIGHTLY}" ]; then
  if [ "${TEST_PLAYBOOKS_JIRA_TICKETS,,}" == "true" ]; then
    echo "This is a nightly build, converting the results to Jira issues and exiting with 0"
    echo "The current directory is ${CURRENT_DIR}"
    python3 "${CURRENT_DIR}/Tests/scripts/convert_test_playbook_result_to_jira_issues.py" --artifacts_path "${ARTIFACTS_FOLDER_INSTANCE}"
    exit_on_error $? "Failed to convert the Test playbook results to Jira issues"

    echo "Finished converting the Test playbook results to Jira issues, exiting with 0"
    exit 0  # Exiting with 0 so that the build will not fail, because we successfully converted the results to Jira issues.
  else
    echo "This is a nightly build, but TEST_PLAYBOOKS_JIRA_TICKETS is not set to true"
    echo "Exiting with the print summary exit code:${summary_exit_code}"
    exit "${summary_exit_code}"
  fi
else
  echo "This is not a nightly build, Exiting with the print summary exit code:${summary_exit_code}"
  exit "${summary_exit_code}"
fi

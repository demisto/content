#!/usr/bin/env bash

if [ -n "${NIGHTLY}" ]; then
  if [ "${TEST_PLAYBOOKS_JIRA_TICKETS,,}" == "true" ]; then
    echo "This is a nightly build, converting the results to Jira issues and exiting with 0"
    echo "The current directory is ${CURRENT_DIR}"
    python3 "${CURRENT_DIR}/Tests/scripts/convert_test_playbook_result_to_jira_issues.py" --artifacts_path "${ARTIFACTS_FOLDER}"
    exit_code=$?
    if [[ "${exit_code}" -ne 0 ]]; then
      echo "Failed to convert the Test playbook results to Jira issues, exiting code:${exit_code}"
      exit ${exit_code}
    fi
    echo "Finished converting the Test playbook results to Jira issues, exiting with 0"
    exit 0  # Exiting with 0 so that the build will not fail, because we successfully converted the results to Jira issues.
  else
    echo "This is a nightly build, but TEST_PLAYBOOKS_JIRA_TICKETS is not set to true, exiting with ${exit_code}"
    exit "${exit_code}"
  fi
else
  echo "This is not a nightly build, exiting with ${exit_code}"
  exit "${exit_code}"
fi

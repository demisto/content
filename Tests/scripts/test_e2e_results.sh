#!/usr/bin/env bash

echo "Starting the e2e test summary script - Server type: ${SERVER_TYPE}, Product type: ${PRODUCT_TYPE}"

if [[ -n "${NIGHTLY}" ]]; then
  python3 ./Tests/Marketplace/print_e2e_test_summary.py --artifacts-path "${ARTIFACTS_FOLDER}"
  summary_exit_code=$?
else
  summary_exit_code=0
  echo "This is not a nightly build, not running e2e test summary script"
fi

exit "${summary_exit_code}"

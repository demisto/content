#!/usr/bin/env bash

CLOUD_SERVERS_PATH=$(cat $CLOUD_SERVERS_FILE)
echo ${CLOUD_API_KEYS} > "cloud_api_keys.json"

if [[ "${INSTANCE_ROLE}" == "XSIAM" ]]; then

  if [[ -z "${CLOUD_CHOSEN_MACHINE_IDS}" ]]; then
    echo "CLOUD_CHOSEN_MACHINE_IDS is not defined, exiting..."
    exit 1
  else
    exit_code=0
    IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
    for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
      echo "Running end-to-end tests on ${CLOUD_CHOSEN_MACHINE_ID}"
      python3 -m pytest ./Tests/tests_end_to_end_xsiam -v --cloud_machine "${CLOUD_CHOSEN_MACHINE_ID}" --cloud_servers_path "${CLOUD_SERVERS_PATH}" --cloud_servers_api_keys "cloud_api_keys.json" --disable-warnings
      if [[ $? -ne 0 ]]; then
        exit_code=1
      fi
    done
    echo "Finished running end-to-end tests on ${CLOUD_CHOSEN_MACHINE_IDS} with exit code ${exit_code}"
    exit "${exit_code}"
  fi
else
  echo "Not running end to end tests on ${INSTANCE_ROLE}, exiting..."
  exit 0
fi


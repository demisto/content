#!/usr/bin/env bash

function exit_on_error {
    if [ "${1}" -ne 0 ]; then
        echo "ERROR: ${2}, exiting with code ${1}" 1>&2
        exit "${1}"
    fi
}

if [ -n "${CLOUD_SERVERS_FILE}" ]; then
  CLOUD_SERVERS_PATH=$(cat "${CLOUD_SERVERS_FILE}")
  echo "CLOUD_SERVERS_PATH is set to: ${CLOUD_SERVERS_PATH}"
else
  exit_on_error 1 "CLOUD_SERVERS_FILE is not set"
fi

if [ -n "${CLOUD_API_KEYS}" ]; then
  if [ "${TEST_XDR_ENV}" == "true" ]; then
    cat "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
  else
    echo "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
  fi
fi



python3 ./Tests/Marketplace/reinstall_packs.py --cloud_machine "${CLOUD_CHOSEN_MACHINE_IDS}" \
  --cloud_servers_path "${CLOUD_SERVERS_PATH}" --cloud_servers_api_keys "cloud_api_keys.json" \
  --non-removable-packs "${NON_REMOVABLE_PACKS}" --build-number "${CI_PIPELINE_ID}" \
  --packs_to_reinstall "${ARTIFACTS_FOLDER_SERVER_TYPE}/packs_reinstall_to_test.txt"
exit_on_error $? "Failed to re-install packs for cloud machines:${CLOUD_CHOSEN_MACHINE_IDS}"

echo "Successfully finished uninstalling packs from cloud machines"
exit 0


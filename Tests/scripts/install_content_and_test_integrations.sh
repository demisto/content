#!/usr/bin/env bash

function exit_on_error {
    if [ "${1}" -ne 0 ]; then
        echo "ERROR: ${2}, exiting with code ${1}" 1>&2
        exit "${1}"
    fi
}

SECRET_CONF_PATH=$(cat secret_conf_path)
if [ -n "${CLOUD_SERVERS_FILE}" ]; then
  CLOUD_SERVERS_PATH=$(cat "${CLOUD_SERVERS_FILE}")
  echo "CLOUD_SERVERS_PATH is set to: ${CLOUD_SERVERS_PATH}"
fi
if [ -n "${CLOUD_API_KEYS}" ]; then
  if [ "${TEST_XDR_ENV}" == "true" ]; then
    cat "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
  else
    echo "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
  fi
fi

CONF_PATH="./Tests/conf.json"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false

if [ -f ./Tests/test_pack.zip ]; then
  echo "Copying test_pack.zip to artifacts folder:${ARTIFACTS_FOLDER}"
  cp ./Tests/test_pack.zip "$ARTIFACTS_FOLDER"
  exit_on_error $? "Failed to copy test_pack.zip to artifacts folder:${ARTIFACTS_FOLDER}"
else
  echo "test_pack.zip was not found in the build directory, skipping..."
fi

echo "Starting $0 script instance role:${INSTANCE_ROLE}, Server type:${SERVER_TYPE} nightly:${IS_NIGHTLY}"

if [[ "${SERVER_TYPE}" == "XSIAM" ]] || [[ "${SERVER_TYPE}" == "XSOAR SAAS" ]]; then
  if [ -n "${CLOUD_CHOSEN_MACHINE_IDS}" ]; then
    IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
    exit_code=0
    for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
      python3 ./Tests/configure_and_test_integration_instances.py -u "$USERNAME" -p "$PASSWORD" -c "$CONF_PATH" \
        -s "$SECRET_CONF_PATH" --tests_to_run "${ARTIFACTS_FOLDER_SERVER_TYPE}/filter_file.txt" \
        --pack_ids_to_install "${ARTIFACTS_FOLDER_SERVER_TYPE}/content_packs_to_install.txt" -g "$GIT_SHA1" --ami_env "${INSTANCE_ROLE}" \
        -n "${IS_NIGHTLY}" --branch "$CI_COMMIT_BRANCH" --build-number "$CI_PIPELINE_ID" -sa "$GCS_MARKET_KEY" \
        --server-type "${SERVER_TYPE}" --cloud_machine "${CLOUD_CHOSEN_MACHINE_ID}" --cloud_servers_path "$CLOUD_SERVERS_PATH" \
        --cloud_servers_api_keys "cloud_api_keys.json" --marketplace_name "$MARKETPLACE_NAME" \
        --artifacts_folder "$ARTIFACTS_FOLDER" --marketplace_buckets "$GCS_MACHINES_BUCKET" \
        --test_pack_path "${ARTIFACTS_FOLDER_SERVER_TYPE}" --content_root "."
      if [ $? -ne 0 ]; then
        exit_code=1
        echo "Failed to run configure_and_test_integration_instances.py script on ${CLOUD_CHOSEN_MACHINE_ID}"
      fi
    done
    exit_on_error "${exit_code}" "Finished $0 script"

    echo "Finished $0 successfully"
    exit 0
  else
    exit_on_error 1 "No machines were chosen"
  fi
elif [[ "${SERVER_TYPE}" == "XSOAR" ]]; then
    python3 ./Tests/configure_and_test_integration_instances.py -u "$USERNAME" -p "$PASSWORD" -c "$CONF_PATH" \
      -s "$SECRET_CONF_PATH" --tests_to_run "${ARTIFACTS_FOLDER_SERVER_TYPE}/filter_file.txt"  \
      --pack_ids_to_install "${ARTIFACTS_FOLDER_SERVER_TYPE}/content_packs_to_install.txt" -g "$GIT_SHA1" --ami_env "${INSTANCE_ROLE}" \
      --is-nightly "${IS_NIGHTLY}" --branch "$CI_COMMIT_BRANCH" --build-number "$CI_PIPELINE_ID" -sa "$GCS_MARKET_KEY" \
      --server-type "${SERVER_TYPE}"  --cloud_machine "${CLOUD_CHOSEN_MACHINE_ID}" \
      --cloud_servers_path "$CLOUD_SERVERS_PATH" --cloud_servers_api_keys "cloud_api_keys.json" \
      --marketplace_name "$MARKETPLACE_NAME" --artifacts_folder "$ARTIFACTS_FOLDER" --marketplace_buckets "$GCS_MACHINES_BUCKET" \
      --test_pack_path "${ARTIFACTS_FOLDER_SERVER_TYPE}" --content_root "."
    exit_on_error $? "Failed to $0 script"

    echo "Finished $0 successfully"
    exit 0
else
  exit_on_error 1 "Unknown server type: ${SERVER_TYPE}"
fi

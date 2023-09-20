#!/usr/bin/env bash

SECRET_CONF_PATH=$(cat secret_conf_path)
CLOUD_SERVERS_PATH=$(cat "${CLOUD_SERVERS_FILE}")
echo "${CLOUD_API_KEYS}" > "cloud_api_keys.json"

CONF_PATH="./Tests/conf.json"
IS_NIGHTLY=false

if [ -n "${NIGHTLY}" ]; then
  IS_NIGHTLY=true
fi

if [ -f ./Tests/test_pack.zip ]; then
  echo "Copying test_pack.zip to artifacts folder:${ARTIFACTS_FOLDER}"
  cp ./Tests/test_pack.zip "$ARTIFACTS_FOLDER"
  exit_code=$?
  if [ ${exit_code} -ne 0 ]; then
    echo "Failed to copy test_pack.zip to artifacts folder:${ARTIFACTS_FOLDER} - Exiting with code ${exit_code}"
    exit ${exit_code}
  fi
else
  echo "test_pack.zip was not found in the build directory, skipping..."
fi

echo "Starting configure_and_test_integration_instances.sh script nightly=${IS_NIGHTLY}"

if [ -n "${CLOUD_CHOSEN_MACHINE_IDS}" ]; then
  IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
  exit_code=0
  for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
    python3 ./Tests/configure_and_test_integration_instances.py -u "$USERNAME" -p "$PASSWORD" -c "$CONF_PATH" -s "$SECRET_CONF_PATH" --tests_to_run "$ARTIFACTS_FOLDER/filter_file.txt"  --pack_ids_to_install "$ARTIFACTS_FOLDER/content_packs_to_install.txt" -g "$GIT_SHA1" --ami_env "$1" -n $IS_NIGHTLY --branch "$CI_COMMIT_BRANCH" --build-number "$CI_PIPELINE_ID" -sa "$GCS_MARKET_KEY" --build_object_type "$2" --cloud_machine "${CLOUD_CHOSEN_MACHINE_ID}" --cloud_servers_path "$CLOUD_SERVERS_PATH" --cloud_servers_api_keys "cloud_api_keys.json" --marketplace_name "$MARKETPLACE_NAME" --artifacts_folder "$ARTIFACTS_FOLDER" --marketplace_buckets "$GCS_MACHINES_BUCKET"
    if [ $? -ne 0 ]; then
      exit_code=1
        echo "Failed to configure_and_test_integration_instances.sh script on ${CLOUD_CHOSEN_MACHINE_ID}"
    fi
  done
  echo "Finished configure_and_test_integration_instances.sh script with exit code ${exit_code}"
  exit ${exit_code}
else
  echo "No machines were chosen"
fi

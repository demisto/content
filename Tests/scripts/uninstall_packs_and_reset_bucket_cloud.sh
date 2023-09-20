#!/usr/bin/env bash

function exit_on_error {
    if [ "${1}" -ne 0 ]; then
        echo "ERROR: ${2}, exiting with code ${1}"
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
  echo "${CLOUD_API_KEYS}" > "cloud_api_keys.json"
fi

if [[ -z "${CLOUD_CHOSEN_MACHINE_IDS}" ]]; then
  exit_on_error 1 "CLOUD_CHOSEN_MACHINE_IDS is not defined"
else
  gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" > auth.out 2>&1
  exit_on_error $? "Failed to authenticate with GCS_MARKET_KEY"

  exit_code=0
  IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
  for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
    echo "Copying prod bucket to ${CLOUD_CHOSEN_MACHINE_ID} bucket."
    gsutil -m cp -r "gs://$GCS_SOURCE_BUCKET/content" "gs://$GCS_MACHINES_BUCKET/${CLOUD_CHOSEN_MACHINE_ID}/" > "$ARTIFACTS_FOLDER/Copy_prod_bucket_to_cloud_machine_cleanup.log" 2>&1
    exit_on_error $? "Failed to copy prod bucket to ${CLOUD_CHOSEN_MACHINE_ID} bucket"
  done

  echo "sleeping 120 seconds"
  sleep 120

  python3 ./Tests/Marketplace/search_and_uninstall_pack.py --cloud_machine "${CLOUD_CHOSEN_MACHINE_IDS}" --cloud_servers_path "${CLOUD_SERVERS_PATH}" --cloud_servers_api_keys "cloud_api_keys.json" --unremovable_packs "${UNREMOVABLE_PACKS}" --one-by-one --build-number "${CI_PIPELINE_ID}"
  exit_on_error $? "Failed to uninstall packs from cloud machines:${CLOUD_CHOSEN_MACHINE_IDS}"

  echo "Finished uninstalling packs from cloud machines with exit code ${exit_code}"
  exit "${exit_code}"
fi

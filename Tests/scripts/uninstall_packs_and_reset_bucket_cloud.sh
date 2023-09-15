#!/usr/bin/env bash

CLOUD_SERVERS_PATH=$(cat "${CLOUD_SERVERS_FILE}")
echo "${CLOUD_API_KEYS}" > "cloud_api_keys.json"

if [[ -z "${CLOUD_CHOSEN_MACHINE_IDS}" ]]; then
  echo "CLOUD_CHOSEN_MACHINE_IDS is not defined, exiting with exit code 1"
  exit 1
else
  gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" > auth.out 2>&1
  if [ $? -ne 0 ]; then
    echo "Failed to authenticate with GCS_MARKET_KEY"
    exit 1
  fi

  exit_code=0
  IFS=', ' read -r -A  CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
  for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
    echo "Copying prod bucket to ${CLOUD_CHOSEN_MACHINE_ID} bucket."
    gsutil -m cp -r "gs://$GCS_SOURCE_BUCKET/content" "gs://$GCS_MACHINES_BUCKET/${CLOUD_CHOSEN_MACHINE_ID}/" > "$ARTIFACTS_FOLDER/Copy_prod_bucket_to_cloud_machine_cleanup.log" 2>&1
    if [ $? -ne 0 ]; then
      echo "Failed to copy prod bucket to ${CLOUD_CHOSEN_MACHINE_ID} bucket."
      exit_code=1
    fi
    echo "sleeping 120 seconds"
    sleep 120
    python3 ./Tests/Marketplace/search_and_uninstall_pack.py --cloud_machine "${CLOUD_CHOSEN_MACHINE_ID}" --cloud_servers_path "${CLOUD_SERVERS_PATH}" --cloud_servers_api_keys "cloud_api_keys.json" --unremovable_packs "${UNREMOVABLE_PACKS}" --one-by-one --build-number "$CI_PIPELINE_ID"
    if [ $? -ne 0 ]; then
      echo "Failed to uninstall packs from ${CLOUD_CHOSEN_MACHINE_ID} machine."
      exit_code=1
    fi
  done
  echo "Finished uninstalling packs from cloud machines with exit code ${exit_code}"
  exit "${exit_code}"
fi

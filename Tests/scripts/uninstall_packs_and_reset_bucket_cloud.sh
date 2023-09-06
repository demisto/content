#!/usr/bin/env bash

# exit on errors
set -e

CLOUD_SERVERS_PATH=$(cat $CLOUD_SERVERS_FILE)
echo ${CLOUD_API_KEYS} > "cloud_api_keys.json"

if [[ -z ${CLOUD_CHOSEN_MACHINE_ID} ]]; then
  echo "CLOUD_CHOSEN_MACHINE_ID is not defined, exiting..."
else
  gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" > auth.out 2>&1
  echo "Copying prod bucket to $CLOUD_CHOSEN_MACHINE_ID bucket."
  gsutil -m cp -r "gs://$GCS_SOURCE_BUCKET/content" "gs://$GCS_MACHINES_BUCKET/$CLOUD_CHOSEN_MACHINE_ID/" > "$ARTIFACTS_FOLDER/Copy_prod_bucket_to_cloud_machine_cleanup.log" 2>&1
  echo "sleeping 120 seconds"
  sleep 120
  python3 ./Tests/Marketplace/search_and_uninstall_pack.py --cloud_machine $CLOUD_CHOSEN_MACHINE_ID --cloud_servers_path $CLOUD_SERVERS_PATH --cloud_servers_api_keys "cloud_api_keys.json" --unremovable_packs $UNREMOVABLE_PACKS --one-by-one --build-number "$CI_PIPELINE_ID"
fi

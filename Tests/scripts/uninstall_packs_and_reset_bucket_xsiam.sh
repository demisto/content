#!/usr/bin/env bash

# exit on errors
set -e

if [[ -z ${XSIAM_CHOSEN_MACHINE_ID} ]]; then
  echo "XSIAM_CHOSEN_MACHINE_ID is not defiened, exiting..."
else
  gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" > auth.out 2>&1
  echo "Copying prod bucket to $XSIAM_CHOSEN_MACHINE_ID bucket."
  gsutil -m cp -r "gs://$GCS_SOURCE_BUCKET/content" "$GCS_MACHINES_BUCKET/$XSIAM_CHOSEN_MACHINE_ID/" > "$ARTIFACTS_FOLDER/Copy_prod_bucket_to_xsiam_machine_cleanup.log" 2>&1
  python3 ./Tests/Marketplace/search_and_uninstall_pack.py --xsiam_machine $XSIAM_CHOSEN_MACHINE_ID --xsiam_servers_path $CLOUD_SERVERS_PATH --xsiam_servers_api_keys $CLOUD_API_KEYS
fi


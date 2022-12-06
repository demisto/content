#!/usr/bin/env bash

# exit on errors
set -e

echo "CLOUD_SERVERS_FILE before cat is $CLOUD_API_KEYS"


CLOUD_SERVERS_PATH=$(cat $CLOUD_SERVERS_FILE)
echo ${CLOUD_API_KEYS} > CLOUD_API_KEYS_FILE

echo "CLOUD_API_KEYS_FILE is $CLOUD_API_KEYS_FILE"
echo "XSIAM_API_KEYS is $XSIAM_API_KEYS"


if [[ -z ${XSIAM_CHOSEN_MACHINE_ID} ]]; then
  echo "XSIAM_CHOSEN_MACHINE_ID is not defiened, exiting..."
else
  gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" > auth.out 2>&1
  echo "Copying prod bucket to $XSIAM_CHOSEN_MACHINE_ID bucket."
  gsutil -m cp -r "gs://$GCS_PRODUCTION_V2_BUCKET/content" "gs://marketplace-v2-dist-dev/upload-flow/builds-xsiam/$XSIAM_CHOSEN_MACHINE_ID/" > "$ARTIFACTS_FOLDER/Copy_prod_bucket_to_xsiam_machine_cleanup.log" 2>&1
  python3 ./Tests/Marketplace/search_and_uninstall_pack.py --xsiam_machine $XSIAM_CHOSEN_MACHINE_ID --cloud_servers_path $CLOUD_SERVERS_PATH --cloud_servers_api_keys $CLOUD_API_KEYS_FILE
fi


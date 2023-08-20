CLOUD_SERVERS_PATH=$(cat "${CLOUD_SERVERS_FILE}")

if [ -n "${CLOUD_CHOSEN_MACHINE_ID}" ]
then
  echo "The tests run on machine: $CLOUD_CHOSEN_MACHINE_ID"
  UI_URL=$(jq -c ". | .\"$CLOUD_CHOSEN_MACHINE_ID\" | .ui_url" "${CLOUD_SERVERS_PATH}")
  BUCKET_URL="https://console.cloud.google.com/storage/browser/$GCS_MACHINES_BUCKET/$CLOUD_CHOSEN_MACHINE_ID/"
  echo "machine url: $UI_URL"
  echo "machine marketplace bucket: $BUCKET_URL"
fi
CLOUD_SERVERS_PATH=$(cat $CLOUD_SERVERS_FILE)

if ! [ -z "$CLOUD_CHOSEN_MACHINE_ID" ]
then
  echo "The tests run on machine: $CLOUD_CHOSEN_MACHINE_ID"
  UI_URL=`cat $CLOUD_SERVERS_PATH | jq -c ". | .\"$CLOUD_CHOSEN_MACHINE_ID\" | .ui_url"`
  BUCKET_URL="https://console.cloud.google.com/storage/browser/$GCS_MACHINES_BUCKET/$CLOUD_CHOSEN_MACHINE_ID/"
  echo "machine url: $UI_URL"
  echo "machine marketplace bucket: $BUCKET_URL"
fi
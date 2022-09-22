XSIAM_SERVERS_PATH=$(cat xsiam_servers_path)

if ! [ -z "$XSIAM_CHOSEN_MACHINE_ID" ]
then
  echo "The tests run on XSIAM machine: $XSIAM_CHOSEN_MACHINE_ID"
  UI_URL=`cat xsiam_servers.json | jq -c ". | .\"$XSIAM_CHOSEN_MACHINE_ID\" | .ui_url"`
  BUCKET_URL="https://console.cloud.google.com/storage/browser/marketplace-v2-dist-dev/upload-flow/builds-xsiam/$XSIAM_CHOSEN_MACHINE_ID/"
  echo "XSIAM machine url: $UI_URL"
  echo "XSIAM machine marketplace bucket: $BUCKET_URL"
fi
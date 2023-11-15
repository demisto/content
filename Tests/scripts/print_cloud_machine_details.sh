#!/usr/bin/env bash

if [ -n "${CLOUD_SERVERS_FILE}" ]; then
  CLOUD_SERVERS_PATH=$(cat "${CLOUD_SERVERS_FILE}")
  echo "CLOUD_SERVERS_PATH is set to: ${CLOUD_SERVERS_PATH}"
else
  echo "CLOUD_SERVERS_FILE is not set, exiting"
  exit 1
fi

if [ -n "${CLOUD_CHOSEN_MACHINE_IDS}" ]; then
  IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
  for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
    UI_URL=$(jq -c ". | .\"${CLOUD_CHOSEN_MACHINE_ID}\" | .ui_url" "${CLOUD_SERVERS_PATH}")
    BUCKET_URL="https://console.cloud.google.com/storage/browser/${GCS_MACHINES_BUCKET}/${CLOUD_CHOSEN_MACHINE_ID}/"
    echo "machine Id: ${CLOUD_CHOSEN_MACHINE_ID}"
    echo "machine url: ${UI_URL}"
    echo "machine marketplace bucket: ${BUCKET_URL}"
  done
else
  echo "No machines were chosen"
fi

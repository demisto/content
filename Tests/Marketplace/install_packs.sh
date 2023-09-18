#!/usr/bin/env bash

echo "starting to install packs ..."

SECRET_CONF_PATH=$(cat secret_conf_path)
XSIAM_SERVERS_PATH=$(cat xsiam_servers_path)

EXTRACT_FOLDER=$(mktemp -d)

INSTANCE_ROLE=${1}
if [ -z "${INSTANCE_ROLE}" ]; then
  echo "INSTANCE_ROLE not set aborting pack installation!"
  exit 1
fi

if [[ ! -f "$GCS_MARKET_KEY" ]]; then
    echo "GCS_MARKET_KEY not set aborting pack installation!"
    exit 1
fi

echo "Trying to authenticate with GCS..."
gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" > auth.out 2>&1
if [ $? -ne 0 ]; then
  echo "Failed to authenticate with GCS, exiting..."
  exit 1
fi
echo "Successfully authenticated with GCS."

echo "starting configure_and_install_packs instance role: ${INSTANCE_ROLE}"
exit_code=0
if [[ "${INSTANCE_ROLE}" == "XSIAM" ]]; then

  if [ -n "${CLOUD_CHOSEN_MACHINE_IDS}" ]; then
    IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
    for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
      python3 ./Tests/Marketplace/configure_and_install_packs.py -s "$SECRET_CONF_PATH" --ami_env "${INSTANCE_ROLE}" --branch "$CI_COMMIT_BRANCH" --build_number "$CI_PIPELINE_ID" --service_account $GCS_MARKET_KEY -e "$EXTRACT_FOLDER" --cloud_machine "${CLOUD_CHOSEN_MACHINE_ID}" --cloud_servers_path ${XSIAM_SERVERS_PATH} --pack_ids_to_install "$ARTIFACTS_FOLDER/content_packs_to_install.txt" --cloud_servers_api_keys $XSIAM_API_KEYS
      if [ $? -ne 0 ]; then
        exit_code=1
      fi
    done
    echo "Finished configure_and_install_packs script with exit code ${exit_code}"
    exit "${exit_code}"
  else
    echo "No machines were chosen, exiting with exit code 1"
    exit 1
  fi
else
  # Running on XSOAR instance roles
  python3 ./Tests/Marketplace/configure_and_install_packs.py -s "$SECRET_CONF_PATH" --ami_env "${INSTANCE_ROLE}" --branch "$CI_COMMIT_BRANCH" --build_number "$CI_PIPELINE_ID" --service_account $GCS_MARKET_KEY -e "$EXTRACT_FOLDER" --pack_ids_to_install "$ARTIFACTS_FOLDER/content_packs_to_install.txt"
  if [ $? -ne 0 ]; then
    exit_code=1
  fi
  echo "Finished configure_and_install_packs script with exit code ${exit_code}"
  exit "${exit_code}"
fi

#!/usr/bin/env bash

function exit_on_error {
    if [ "${1}" -ne 0 ]; then
        echo "ERROR: ${2}, exiting with code ${1}" 1>&2
        exit "${1}"
    fi
}

echo "starting to install packs ..."

SECRET_CONF_PATH=$(cat secret_conf_path)
XSIAM_SERVERS_PATH=$(cat xsiam_servers_path)

EXTRACT_FOLDER=$(mktemp -d)

INSTANCE_ROLE=${1}
if [ -z "${INSTANCE_ROLE}" ]; then
  exit_on_error 1 "INSTANCE_ROLE not set aborting pack installation"
fi

if [[ ! -f "$GCS_MARKET_KEY" ]]; then
    exit_on_error 1 "GCS_MARKET_KEY not set aborting pack installation"
fi

echo "Trying to authenticate with GCS..."
gcloud auth activate-service-account --key-file="$GCS_MARKET_KEY" > auth.out 2>&1
exit_on_error $? "Failed to authenticate with GCS"

echo "Successfully authenticated with GCS."

echo "starting configure_and_install_packs instance role: ${INSTANCE_ROLE}"

if [[ "${INSTANCE_ROLE}" == "XSIAM" ]]; then
  if [ -n "${CLOUD_CHOSEN_MACHINE_IDS}" ]; then
    exit_code=0
    IFS=', ' read -r -a CLOUD_CHOSEN_MACHINE_ID_ARRAY <<< "${CLOUD_CHOSEN_MACHINE_IDS}"
    for CLOUD_CHOSEN_MACHINE_ID in "${CLOUD_CHOSEN_MACHINE_ID_ARRAY[@]}"; do
      python3 ./Tests/Marketplace/configure_and_install_packs.py -s "$SECRET_CONF_PATH" --ami_env "${INSTANCE_ROLE}" --branch "$CI_COMMIT_BRANCH" --build_number "$CI_PIPELINE_ID" --service_account $GCS_MARKET_KEY -e "$EXTRACT_FOLDER" --cloud_machine "${CLOUD_CHOSEN_MACHINE_ID}" --cloud_servers_path ${XSIAM_SERVERS_PATH} --pack_ids_to_install "$ARTIFACTS_FOLDER/content_packs_to_install.txt" --cloud_servers_api_keys $XSIAM_API_KEYS
      if [ $? -ne 0 ]; then
        exit_code=1
        echo "Failed to install packs on machine ${CLOUD_CHOSEN_MACHINE_ID}"
      fi
    done

    exit_on_error "${exit_code}" "Finished configure_and_install_packs script"

    echo "Finished configure_and_install_packs successfully"
    exit 0
  else
    exit_on_error 1 "No machines were chosen"
  fi
else
  # Running on XSOAR instance roles
  python3 ./Tests/Marketplace/configure_and_install_packs.py -s "$SECRET_CONF_PATH" --ami_env "${INSTANCE_ROLE}" --branch "$CI_COMMIT_BRANCH" --build_number "$CI_PIPELINE_ID" --service_account $GCS_MARKET_KEY -e "$EXTRACT_FOLDER" --pack_ids_to_install "$ARTIFACTS_FOLDER/content_packs_to_install.txt"
  exit_on_error "$?" "Finished configure_and_install_packs script"

  echo "Finished configure_and_install_packs successfully"
  exit 0
fi

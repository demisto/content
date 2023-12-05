#!/usr/bin/env bash

SECRET_CONF_PATH="./conf_secret.json"
echo ${SECRET_CONF_PATH} > secret_conf_path

XSIAM_SERVERS_PATH="./xsiam_servers.json"
echo ${XSIAM_SERVERS_PATH} > xsiam_servers_path

XSOAR_NG_SERVERS_PATH="./xsoar_ng_servers.json"
echo ${XSOAR_NG_SERVERS_PATH} > xsoar_ng_servers_path

DEMISTO_LIC_PATH="./demisto.lic"
echo ${DEMISTO_LIC_PATH} > demisto_lic_path

DEMISTO_PACK_SIGNATURE_UTIL_PATH="./signDirectory"
echo ${DEMISTO_PACK_SIGNATURE_UTIL_PATH} > demisto_pack_sig_util_path

cp ./content-test-conf/secrets_build_scripts/google_secret_manager_handler.py ./Tests/scripts
cp ./content-test-conf/secrets_build_scripts/add_secrets_file_to_build.py ./Tests/scripts
cp ./content-test-conf/secrets_build_scripts/merge_and_delete_dev_secrets.py ./Tests/scripts
cp -r ./content-test-conf/demisto.lic ${DEMISTO_LIC_PATH}
cp -r ./content-test-conf/signDirectory ${DEMISTO_PACK_SIGNATURE_UTIL_PATH}

echo "Cloning PrivatePacks"
cp -r ./content-test-conf/content/PrivatePacks/* ./Packs
echo "Cloned PrivatePacks"

if [[ "${NIGHTLY}" == "true" || "${EXTRACT_PRIVATE_TESTDATA}" == "true" ]]; then
    python ./Tests/scripts/extract_content_test_conf.py --content-path . --content-test-conf-path ./content-test-conf --missing-content-packs-test-conf "${ARTIFACTS_FOLDER_SERVER_TYPE}/missing_content_packs_test_conf.txt"
fi

cp -r ./infra/xsiam_servers.json $XSIAM_SERVERS_PATH
cp -r ./infra/xsoar_ng_servers.json $XSOAR_NG_SERVERS_PATH

cp ./infra/gcp ./gcp

echo "Successfully using! content-test-conf and infra repositories"

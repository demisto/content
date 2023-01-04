#!/usr/bin/env bash
set +e

# replace slashes ('/') in the branch name, if exist, with underscores ('_')
UNDERSCORE_BRANCH=${CI_COMMIT_BRANCH//\//_}

#download awsinstancetool
echo "Getting conf from branch $UNDERSCORE_BRANCH (fallback to master)"

SECRET_CONF_PATH="./conf_secret.json"
echo ${SECRET_CONF_PATH} > secret_conf_path

XSIAM_SERVERS_PATH="./xsiam_servers.json"
echo ${XSIAM_SERVERS_PATH} > xsiam_servers_path

DEMISTO_LIC_PATH="./demisto.lic"
echo ${DEMISTO_LIC_PATH} > demisto_lic_path

DEMISTO_PACK_SIGNATURE_UTIL_PATH="./signDirectory"
echo ${DEMISTO_PACK_SIGNATURE_UTIL_PATH} > demisto_pack_sig_util_path

# download configuration files from Gitlab repo
echo "clone content-test-conf from branch: $UNDERSCORE_BRANCH in content-test-conf"
git clone --depth=1 https://gitlab-ci-token:${CI_JOB_TOKEN}@code.pan.run/xsoar/content-test-conf.git --branch $UNDERSCORE_BRANCH
if [ "$?" != "0" ]; then
    echo "No such branch in content-test-conf: $UNDERSCORE_BRANCH , falling back to master"
    git clone --depth=1 https://gitlab-ci-token:${CI_JOB_TOKEN}@code.pan.run/xsoar/content-test-conf.git
fi
cp -r ./content-test-conf/awsinstancetool ./Tests/scripts/awsinstancetool
cp -r ./content-test-conf/demisto.lic $DEMISTO_LIC_PATH
cp -r ./content-test-conf/signDirectory $DEMISTO_PACK_SIGNATURE_UTIL_PATH
cp -r ./content-test-conf/xsiam_servers.json $XSIAM_SERVERS_PATH

if [[ "$IS_NIGHTLY" == "true" ]] || [[ "$EXTRACT_MODELING_RULE_TESTDATA_FILES" == "true" && "$UNDERSCORE_BRANCH" != "master" ]]; then
    cp -r ./content-test-conf/modelingrules ./modelingrules
fi

if [[ -d ./modelingrules ]]; then
    echo "Copying modeling rule testdata files to their respective directories"
    ls -RlAh ./modelingrules
    # Copy testdata files from 'modelingrules' directory that was extracted to root directory into their respective pack destinations
    mapfile -t testdata_files < <(find ./modelingrules -name '*.json')
    for testdata_file in "${testdata_files[@]}"; do
        # strip './' prefix
        dest_without_curdir="${testdata_file#*/}"
        # strip 'modelingrules/' prefix
        pack_dest="${dest_without_curdir#*/}"
        echo "Copying $testdata_file --> $pack_dest"
        cp "$testdata_file" "$pack_dest"
    done
    echo "Deleting ./modelingrules directory"
    rm -rf ./modelingrules
fi

rm -rf ./content-test-conf

set -e
echo "Successfully downloaded configuration files"

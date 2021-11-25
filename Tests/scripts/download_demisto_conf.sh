#!/usr/bin/env bash
set +e

# replace slashes ('/') in the branch name, if exist, with underscores ('_')
UNDERSCORE_BRANCH=${CI_COMMIT_BRANCH//\//_}

#download awsinstancetool
echo "Getting conf from branch $UNDERSCORE_BRANCH (fallback to master)"

SECRET_CONF_PATH="./conf_secret.json"
echo ${SECRET_CONF_PATH} > secret_conf_path

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
cp -r ./content-test-conf/conf.json $SECRET_CONF_PATH
cp -r ./content-test-conf/signDirectory $DEMISTO_PACK_SIGNATURE_UTIL_PATH
rm -rf ./content-test-conf

set -e
echo "Successfully downloaded configuration files"

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

# download configuration files from github repo
echo "CLONING GITLAB"
git clone --depth=1 https://gitlab-ci-token:${CI_JOB_TOKEN}@code.pan.run/xsoar/content-test-conf.git --branch $UNDERSCORE_BRANCH
echo "$(ls)"
if [ "$?" != "0" ]; then
    echo "No such branch in content-test-conf: $UNDERSCORE_BRANCH , falling back to master"
    git clone --depth=1 https://gitlab-ci-token:${CI_JOB_TOKEN}@code.pan.run/xsoar/content-test-conf.git
    cp -r ./content-test-conf-master/awsinstancetool ./Tests/scripts/awsinstancetool
    cp -r ./content-test-conf-master/demisto.lic $DEMISTO_LIC_PATH
    cp -r ./content-test-conf-master/conf.json $SECRET_CONF_PATH
    cp -r ./content-test-conf-master/signDirectory $DEMISTO_PACK_SIGNATURE_UTIL_PATH
    rm -rf ./content-test-conf-master
    rm -rf ./test_configuration.zip
  else
    cp -r ./content-test-conf-$UNDERSCORE_BRANCH/awsinstancetool ./Tests/scripts/awsinstancetool
    cp -r ./content-test-conf-$UNDERSCORE_BRANCH/demisto.lic $DEMISTO_LIC_PATH
    cp -r ./content-test-conf-$UNDERSCORE_BRANCH/conf.json $SECRET_CONF_PATH
    cp -r ./content-test-conf-$UNDERSCORE_BRANCH/signDirectory $DEMISTO_PACK_SIGNATURE_UTIL_PATH
    rm -rf ./content-test-conf-$UNDERSCORE_BRANCH
    rm -rf ./test_configuration.zip
fi

set -e
echo "Successfully downloaded configuration files"

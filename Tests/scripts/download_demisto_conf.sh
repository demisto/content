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

# download configuration files from Gitlab repo
echo "clone content-test-conf from branch: $UNDERSCORE_BRANCH in content-test-conf"
git clone --depth=1 https://gitlab-ci-token:${CI_JOB_TOKEN}@code.pan.run/xsoar/content-test-conf.git --branch $UNDERSCORE_BRANCH
if [ "$?" != "0" ]; then
    echo "No such branch in content-test-conf: $UNDERSCORE_BRANCH , falling back to master"
    git clone --depth=1 https://gitlab-ci-token:${CI_JOB_TOKEN}@code.pan.run/xsoar/content-test-conf.git
fi
mv ./content-test-conf/conf.json $SECRET_CONF_PATH
mv ./content-test-conf/xsiam_servers.json $XSIAM_SERVERS_PATH
rm -rf ./content-test-conf

echo "clone infra from branch: $UNDERSCORE_BRANCH in content-test-conf"
git clone --depth=1 https://gitlab-ci-token:${CI_JOB_TOKEN}@code.pan.run/xsoar/infra.git --branch $UNDERSCORE_BRANCH
if [ "$?" != "0" ]; then
    echo "No such branch in infra: $UNDERSCORE_BRANCH , falling back to master"
    git clone --depth=1 https://gitlab-ci-token:${CI_JOB_TOKEN}@code.pan.run/xsoar/infra.git
fi
mv -r ./infra/gcp ./gcp
rm -rf ./infra

set -e
echo "Successfully downloaded configuration files"

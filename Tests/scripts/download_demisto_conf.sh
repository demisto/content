#!/usr/bin/env bash
set +e

# replace slashes ('/') in the branch name, if exist, with underscores ('_')
UNDERSCORE_CIRCLE_BRANCH=${CIRCLE_BRANCH//\//_}

#download awsinstancetool
echo "Getting conf from branch $UNDERSCORE_CIRCLE_BRANCH (fallback to master)"

SECRET_CONF_PATH="./conf_secret.json"
echo ${SECRET_CONF_PATH} > secret_conf_path

DEMISTO_LIC_PATH="./demisto.lic"
echo ${DEMISTO_LIC_PATH} > demisto_lic_path

<<<<<<< HEAD
=======
DEMISTO_PACK_SIGNATURE_UTIL_PATH="./signDirectory"
echo ${DEMISTO_PACK_SIGNATURE_UTIL_PATH} > demisto_pack_sig_util_path

DEMISTO_PACK_SIGNATURE_KEY_PATH="./signKey"
echo ${DEMISTO_PACK_SIGNATURE_KEY_PATH} > demisto_pack_sig_key_path

>>>>>>> upstream/master
# download configuration files from github repo
wget --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN" -O ./test_configuration.zip "https://github.com/demisto/content-test-conf/archive/$UNDERSCORE_CIRCLE_BRANCH.zip" --no-check-certificate -q
if [ "$?" != "0" ]; then
    echo "No such branch in content-test-conf: $UNDERSCORE_CIRCLE_BRANCH , falling back to master"
    wget --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN" -O ./test_configuration.zip "https://github.com/demisto/content-test-conf/archive/master.zip" --no-check-certificate -q
    unzip ./test_configuration.zip
    cp -r ./content-test-conf-master/awsinstancetool ./Tests/scripts/awsinstancetool
    cp -r ./content-test-conf-master/demisto.lic $DEMISTO_LIC_PATH
    cp -r ./content-test-conf-master/conf.json $SECRET_CONF_PATH
<<<<<<< HEAD
    if [ -n "${NIGHTLY}" ]
      then
        cp -r ./content-test-conf-master/nightly_instance.json instance.json

      else
        cp -r ./content-test-conf-master/instance.json instance.json
    fi
=======
    cp -r ./content-test-conf-master/signDirectory $DEMISTO_PACK_SIGNATURE_UTIL_PATH
    cp -r ./content-test-conf-master/signKey DEMISTO_PACK_SIGNATURE_KEY_PATH
>>>>>>> upstream/master
    rm -rf ./content-test-conf-master
    rm -rf ./test_configuration.zip
  else
    unzip ./test_configuration.zip
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/awsinstancetool ./Tests/scripts/awsinstancetool
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/demisto.lic $DEMISTO_LIC_PATH
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/conf.json $SECRET_CONF_PATH
<<<<<<< HEAD
    if [ -n "${NIGHTLY}" ]
      then
        cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/nightly_instance.json instance.json

      else
        cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/instance.json instance.json
=======
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/signDirectory $DEMISTO_PACK_SIGNATURE_UTIL_PATH
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/signKey DEMISTO_PACK_SIGNATURE_KEY_PATH
    rm -rf ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH
    rm -rf ./test_configuration.zip
    if [ "$UNDERSCORE_CIRCLE_BRANCH" != "master" ]; then
        echo "ERROR: Found a branch with the same name in contest-test-conf conf.json - $UNDERSCORE_CIRCLE_BRANCH.\n Merge it in order to merge the current branch into content repo."
        exit 1
>>>>>>> upstream/master
    fi
    rm -rf ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH
    rm -rf ./test_configuration.zip
fi

set -e
<<<<<<< HEAD
echo "using instance:"
cat instance.json
=======
>>>>>>> upstream/master
echo "Successfully downloaded configuration files"

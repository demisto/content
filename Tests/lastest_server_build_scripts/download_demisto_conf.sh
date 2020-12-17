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

DEMISTO_SEVERCONF_PATH="./demisto.conf"
echo ${DEMISTO_SEVERCONF_PATH} > demisto_conf_path

DEMISTO_OTC_PATH="./otc.json"
echo ${DEMISTO_OTC_PATH} > demisto_otc_path

DEMISTO_PACK_SIGNATURE_UTIL_PATH="./signDirectory"
echo ${DEMISTO_PACK_SIGNATURE_UTIL_PATH} > demisto_pack_sig_util_path

cat >> "$DEMISTO_SEVERCONF_PATH" <<-EOF
{
  "Server": {
    "HttpsPort": "443"
  },
  "version.control.enabled": false,
  "reputation.calc.algorithm.manual": 3,
  "reputation.calc.algorithm.tasks": 3,
  "log.level": "debug",
  "content.install.always.sync": true,
  "builtin.commands.hidden.getcontext": true,
  "password.policy.default.Enabled": "false"
}
EOF

# download configuration files from github repo
wget --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN" -O ./test_configuration.zip "https://github.com/demisto/content-test-conf/archive/$UNDERSCORE_CIRCLE_BRANCH.zip" --no-check-certificate -q
if [ "$?" != "0" ]; then
    echo "No such branch in content-test-conf: $UNDERSCORE_CIRCLE_BRANCH , falling back to master"
    wget --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN" -O ./test_configuration.zip "https://github.com/demisto/content-test-conf/archive/master.zip" --no-check-certificate -q
    unzip ./test_configuration.zip
    cp -r ./content-test-conf-master/awsinstancetool ./Tests/scripts/awsinstancetool
    cp -r ./content-test-conf-master/demisto.lic $DEMISTO_LIC_PATH
    cp -r ./content-test-conf-master/conf.json $SECRET_CONF_PATH
    cp -r ./content-test-conf-master/signDirectory $DEMISTO_PACK_SIGNATURE_UTIL_PATH
    cp -r ./content-test-conf-master/otc.json $DEMISTO_OTC_PATH

    if [ -n "${NIGHTLY}" ]
      then
        cp -r ./content-test-conf-master/nightly_instance.json instance.json

      else
        cp -r ./content-test-conf-master/instance.json instance.json
    fi
    rm -rf ./content-test-conf-master
    rm -rf ./test_configuration.zip
  else
    unzip ./test_configuration.zip
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/awsinstancetool ./Tests/scripts/awsinstancetool
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/demisto.lic $DEMISTO_LIC_PATH
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/conf.json $SECRET_CONF_PATH
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/signDirectory $DEMISTO_PACK_SIGNATURE_UTIL_PATH
    cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/otc.json $DEMISTO_OTC_PATH
    if [ -n "${NIGHTLY}" ]
      then
        cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/nightly_instance.json instance.json

      else
        cp -r ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH/instance.json instance.json
    fi
    rm -rf ./content-test-conf-$UNDERSCORE_CIRCLE_BRANCH
    rm -rf ./test_configuration.zip
fi

set -e
echo "using instance:"
cat instance.json
echo "Successfully downloaded configuration files"

#!/usr/bin/env bash
set -e

# download configuration file from github repo
echo "Getting conf from branch $CIRCLE_BRANCH (fallback to master)"

SECRET_CONF_PATH="./conf_secret.json"
echo ${SECRET_CONF_PATH} > secret_conf_path

DEMISTO_LIC_PATH="./demisto.lic"
echo ${DEMISTO_LIC_PATH} > demisto_lic_path

DEMISTO_SEVERCONF_PATH="./demisto.conf"
echo ${DEMISTO_SEVERCONF_PATH} > demisto_conf_path

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json?ref=$CIRCLE_BRANCH" -o "$SECRET_CONF_PATH"

NOT_FOUND_MESSAGE=$(cat $SECRET_CONF_PATH | jq '.message')

if [ "$NOT_FOUND_MESSAGE" != 'null' ]
  then
    echo "Branch $CIRCLE_BRANCH does not exists in content-test-conf repo - downloading from master"
    echo "Got message from github=$NOT_FOUND_MESSAGE"

    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json" -o "$SECRET_CONF_PATH"

    echo "Downloading license file..."
    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/demisto.lic" -o "$DEMISTO_LIC_PATH"

    echo "Downloading server conf file..."
    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/server.conf" -o "$DEMISTO_SEVERCONF_PATH"

    echo "Downloading instance conf file..."
    if [ -n "${NIGHTLY}" ]
      then
        curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
          --location "https://api.github.com/repos/demisto/content-test-conf/contents/nightly_instance.json" -o "instance.json"

      else
        curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
          --location "https://api.github.com/repos/demisto/content-test-conf/contents/instance.json" -o "instance.json"

    fi

  else
    echo "Downloading license file..."
    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/demisto.lic?ref=$CIRCLE_BRANCH" -o "$DEMISTO_LIC_PATH"

    echo "Downloading server conf file..."
    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/server.conf?ref=$CIRCLE_BRANCH" -o "$DEMISTO_SEVERCONF_PATH"

    echo "Downloading instance conf file..."
    if [ -n "${NIGHTLY}" ]
      then
        curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
          --location "https://api.github.com/repos/demisto/content-test-conf/contents/nightly_instance.json?ref=$CIRCLE_BRANCH" -o "instance.json"

      else
        curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
          --location "https://api.github.com/repos/demisto/content-test-conf/contents/instance.json?ref=$CIRCLE_BRANCH" -o "instance.json"

    fi

fi
echo "using instance:"
cat instance.json
echo "Successfully downloaded configuration files"

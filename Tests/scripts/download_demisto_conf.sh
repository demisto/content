#!/usr/bin/env bash
set -e

# download configuration file from github repo
echo "Getting conf from branch $CIRCLE_BRANCH (fallback to master)"

SECRET_CONF_PATH="./conf_secret.json"
echo ${SECRET_CONF_PATH} > secret_conf_path

DEMISTO_LIC_PATH="./demisto.lic"
echo ${DEMISTO_LIC_PATH} > demisto_lic_path

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json?ref=$CIRCLE_BRANCH" -o "$SECRET_CONF_PATH"

NOT_FOUND_MESSAGE=$(cat $SECRET_CONF_PATH | jq '.message')

download_extra_files() {
    BRANCH="$1"

    echo "Start downloading extra files from branch $BRANCH.."

    echo "Downloading license file..."
    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/demisto.lic?ref=$BRANCH" -o "$DEMISTO_LIC_PATH"

    echo "Downloading demisto-conf file..."
    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/demisto-conf.json?ref=$BRANCH" -o "$DEMISTO_LIC_PATH"


    echo "Finished downloading extra files from branch $BRANCH"
}


if [ "$NOT_FOUND_MESSAGE" != 'null' ]
  then
    echo "Branch $CIRCLE_BRANCH does not exists in content-test-conf repo - downloading from master"
    echo "Got message from github=$NOT_FOUND_MESSAGE"

    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json" -o "$SECRET_CONF_PATH"

    download_extra_files "master"

  else
    download_extra_files $CIRCLE_BRANCH
fi

echo "Successfully downloaded configuration files"

echo "##### pwd ####"
pwd
echo "##### ls ####"
ls
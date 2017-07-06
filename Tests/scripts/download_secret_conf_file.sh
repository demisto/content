#!/usr/bin/env bash
set -e

# download configuration file from github repo
echo "Getting conf from branch $CIRCLE_BRANCH (fallback to master)"

SECRET_CONF_PATH="./conf_secret.json"
echo ${SECRET_CONF_PATH} > secret_conf_path

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json?ref=$CIRCLE_BRANCH" -o "$SECRET_CONF_PATH"

NOT_FOUND_MESSAGE=$(cat $SECRET_CONF_PATH | jq '.message')

if [ "$NOT_FOUND_MESSAGE" != 'null' ]
  then
    echo "Branch $CIRCLE_BRANCH does not exists in content-test-conf repo - downloading from master"
    echo "Got message from github=$NOT_FOUND_MESSAGE"

    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json" -o "$SECRET_CONF_PATH"
fi

echo "Successfully downloaded secret configuration file to $SECRET_CONF_PATH"
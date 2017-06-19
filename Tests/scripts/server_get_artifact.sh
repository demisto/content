#!/usr/bin/env bash

ACCEPT_TYPE="Accept: application/json"
SERVER_API_URI="https://circleci.com/api/v1/project/demisto/server"
TOKEN_ATTR="circle-token=$SERVER_CI_TOKEN"


ARTIFACT_BUILD_NUM=$(curl -s -H "$ACCEPT_TYPE" "$SERVER_API_URI/tree/master?limit=1&filter=successful&$TOKEN_ATTR" | jq '.[0].build_num')
echo "Getting server artifact for build: ${ARTIFACT_BUILD_NUM}"

SERVER_DOWNLOAD_LINK=$(curl -s -H "$ACCEPT_TYPE" ${SERVER_API_URI}/${ARTIFACT_BUILD_NUM}/artifacts?${TOKEN_ATTR})

echo "SERVER_DOWNLOAD_LINK1: ${SERVER_DOWNLOAD_LINK}"
SERVER_DOWNLOAD_LINK=$($SERVER_DOWNLOAD_LINK | jq '.[].url' -r)


echo "SERVER_DOWNLOAD_LINK2: ${SERVER_DOWNLOAD_LINK}"
SERVER_DOWNLOAD_LINK=$($SERVER_DOWNLOAD_LINK | grep demistoserver)

echo "SERVER_DOWNLOAD_LINK3: ${SERVER_DOWNLOAD_LINK}"

SERVER_DOWNLOAD_LINK=$($SERVER_DOWNLOAD_LINK | grep /0/)

echo "SERVER_DOWNLOAD_LINK4: ${SERVER_DOWNLOAD_LINK}"

exit 0
curl ${SERVER_DOWNLOAD_LINK}?${TOKEN_ATTR} -o demistoserver.sh

ls

echo "Done!"
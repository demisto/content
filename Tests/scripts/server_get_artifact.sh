#!/usr/bin/env bash
ACCEPT_TYPE="Accept: application/json"
SERVER_API_URI="https://circleci.com/api/v1/project/demisto/server"
TOKEN_ATTR="circle-token=$SERVER_CI_TOKEN"

echo "Getting latest build num"

ARTIFACT_BUILD_NUM=$(curl -s -H "$ACCEPT_TYPE" "$SERVER_API_URI/tree/master?limit=1&filter=successful&$TOKEN_ATTR" | jq '.[0].build_num')

echo "ARTIFACT_BUILD_NUM -  $ARTIFACT_BUILD_NUM"
exit 0

SERVER_DOWNLOAD_LINK=$(curl -s -H "$ACCEPT_TYPE" ${SERVER_API_URI}/${ARTIFACT_BUILD_NUM}/artifacts?${TOKEN_ATTR} | jq '.[].url' -r | grep server.tar.gz | grep /0/)

echo "Getting server artifact for build: ${ARTIFACT_BUILD_NUM}"
curl ${SERVER_DOWNLOAD_LINK}?${TOKEN_ATTR} | tar -xz
rm -f server_darwin_amd64 server_windows_amd64.exe

echo "Getting tom artifact"
curl -o tom ${TOM_DOWNLOAD_LINK}?${TOKEN_ATTR}
chmod +x ./tom

echo "Done!"
#!/usr/bin/env bash

ACCEPT_TYPE="Accept: application/json"
SERVER_API_URI="https://circleci.com/api/v1/project/demisto/server"
TOKEN_ATTR="circle-token=$SERVER_CI_TOKEN"
TOKEN_ATTR1="circle-token=blabla"

SERVER_DOWNLOAD_LINK=$(curl -s -H "$ACCEPT_TYPE" ${SERVER_API_URI}/${ARTIFACT_BUILD_NUM}/artifacts?${TOKEN_ATTR})
echo "#####"
echo "$ACCEPT_TYPE" ${SERVER_API_URI}/${ARTIFACT_BUILD_NUM}/artifacts?${TOKEN_ATTR1}
echo "SERVER_DOWNLOAD_LINK: ${SERVER_DOWNLOAD_LINK}"
echo "#####"

exit 0
curl ${SERVER_DOWNLOAD_LINK}?${TOKEN_ATTR} -o demistoserver.sh

ls

echo "Done!"
ACCEPT_TYPE="Accept: application/json"
SERVER_API_URI="https://circleci.com/api/v1/project/demisto/server"
TOKEN_ATTR="circle-token=$1"

if [ -n "${SERVER_BRANCH_NAME}" ]
  then
    _server_branch_name=${SERVER_BRANCH_NAME}

  else
    _server_branch_name="master"

fi

echo "Getting latest build num"
TEMP=$(curl -s -H "$ACCEPT_TYPE" "$SERVER_API_URI/tree/${_server_branch_name}?limit=10&filter=successful&$TOKEN_ATTR")

ARTIFACT_BUILD_NUM=
for i in `seq 0 9`; do
    if [[ $(echo "$TEMP" | jq ".[$i].build_parameters") == "null" ]]; then
        ARTIFACT_BUILD_NUM=$(echo "$TEMP" | jq ".[$i].build_num")
        break
    fi
done

if [[ "$ARTIFACT_BUILD_NUM" = "" ]]; then
    echo "couldn't find successful build"
    exit 1
fi

SERVER_DOWNLOAD_LINK=$(curl -s -H "$ACCEPT_TYPE" ${SERVER_API_URI}/${ARTIFACT_BUILD_NUM}/artifacts?${TOKEN_ATTR} | jq '.[].url' -r | grep demistoserver | grep /0/ | head -n 1)
TEMP_LINK=${SERVER_DOWNLOAD_LINK}?${TOKEN_ATTR}
SERVER_DOWNLOAD_LINK=${TEMP_LINK%$'\r'}

echo "Getting server artifact for build: ${ARTIFACT_BUILD_NUM}"
echo "wget to ${SERVER_DOWNLOAD_LINK}"

wget -O demistoserver.sh "${SERVER_DOWNLOAD_LINK}"

echo "Done!"

ACCEPT_TYPE="Accept: application/json"
SERVER_API_URI="https://circleci.com/api/v1/project/demisto/server"
TOKEN_ATTR="circle-token=$1"

echo "Getting latest build num"


ARTIFACT_BUILD_NUM=32097
if [[ "$ARTIFACT_BUILD_NUM" = "" ]]; then
    echo "couldn't find successful build"
    exit 1
fi

SERVER_DOWNLOAD_LINK=$(curl -s -H "$ACCEPT_TYPE" ${SERVER_API_URI}/${ARTIFACT_BUILD_NUM}/artifacts?${TOKEN_ATTR} | jq '.[].url'-r | grep demistoserver | grep /0/ | head -n 1)
echo $SERVER_DOWNLOAD_LINK
TEMP_LINK=${SERVER_DOWNLOAD_LINK}?${TOKEN_ATTR}
SERVER_DOWNLOAD_LINK=${TEMP_LINK%$'\r'}

echo "Getting server artifact for build: ${ARTIFACT_BUILD_NUM}"
echo "wget to ${SERVER_DOWNLOAD_LINK}"

wget -O demistoserver.sh "${SERVER_DOWNLOAD_LINK}"

echo "Done!"

#!/usr/bin/env bash

ACCEPT_TYPE="Accept: application/json"
SERVER_API_URI="https://circleci.com/api/v1/project/demisto/server"
TOKEN_ATTR="circle-token=$SERVER_CI_TOKEN"

echo WEB_CLIENT_ARTIFACT_VERSION=${WEB_CLIENT_ARTIFACT_VERSION}

if [ -z ${SERVER_CI_TOKEN} ]
then
    echo "Server CI token must be provided"
    exit -1
fi


# Fetch last server master build
SERVER_LAST_BUILD_NUM=$(curl --retry-max-time 0 --retry 5 --max-time 180 -H "$ACCEPT_TYPE" "$SERVER_API_URI/tree/master?limit=1&filter=successful&$TOKEN_ATTR" | jq '.[0].build_num')

echo SERVER_LAST_BUILD_NUM=${SERVER_LAST_BUILD_NUM}
WEB_CLIENT_ARTIFACT_VERSION=${SERVER_LAST_BUILD_NUM}

# Fetch web client Git SHA
WEB_CLIENT_GIT_SHA=$(curl -H "$ACCEPT_TYPE" "$SERVER_API_URI/$WEB_CLIENT_ARTIFACT_VERSION?$TOKEN_ATTR" | jq '.vcs_revision' -r )

echo WEB_CLIENT_GIT_SHA=${WEB_CLIENT_GIT_SHA}

exit 0
#This will replace the app version with correct Git revision
sed -i -- "s/REPLACE_THIS_WITH_WEB_CLIENT_GIT_COMMIT_VERSION/$WEB_CLIENT_GIT_SHA/g" *version/version.go*

WEB_CLIENT_URLS=$(curl -H "$ACCEPT_TYPE" ${SERVER_API_URI}/${WEB_CLIENT_ARTIFACT_VERSION}/artifacts?${TOKEN_ATTR} | jq '.[] .url')

# find the correct web-client artifact url
DOWNLOAD_LINK=""
for url in ${WEB_CLIENT_URLS[@]}
do
   echo url
done

#fetch last web artifact url
#wget --content-disposition ${DOWNLOAD_LINK}?${TOKEN_ATTR} -O web-client.tar
#tar -xvf web-client.tar

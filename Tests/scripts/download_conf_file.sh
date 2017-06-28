# download configuration file from github repo

echo "$CIRCLE_BRANCH"

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
        --remote-name --location "https://api.github.com/repos/demisto/content-test-conf/$CIRCLE_BRANCH/contents/conf.json"

echo "MIDDLE"
cat ./conf.json
echo "#################"

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
        --remote-name --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json"

echo "END"
cat ./conf.json
echo "#################"

echo "Successfully downloaded configuration file"
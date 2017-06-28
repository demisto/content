# download configuration file from github repo

if [ "$CIRCLE_BRANCH" != "master" ];

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
        --remote-name --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json"

ls

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
        --remote-name --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json"

ls

echo "Successfully downloaded configuration file"
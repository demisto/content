# download configuration file from github repo
curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
        --remote-name --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json"

ls

echo "Successfully downloaded configuration file"
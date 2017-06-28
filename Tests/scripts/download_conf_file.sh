# download configuration file from github repo

echo "Getting conf from branch $CIRCLE_BRANCH (fallback to master)"

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/$CIRCLE_BRANCH/conf.json" -o conf.json

echo "MIDDLE"
cat ./conf.json
echo "#################"

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json" -o conf.json

echo "END"
cat ./conf.json
echo "#################"

echo "Successfully downloaded configuration file"
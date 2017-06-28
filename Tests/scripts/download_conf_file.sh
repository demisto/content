# download configuration file from github repo

echo "Getting conf from branch $CIRCLE_BRANCH (fallback to master)"

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json?ref=CIRCLE_BRANCH" -o conf.json

echo "MIDDLE"
cat ./conf.json
echo "#################"

NOT_FOUND_MESSAGE=$(cat ./conf.json | jq '.message')
echo "NOT_FOUND_MESSAGE=$NOT_FOUND_MESSAGE"

if [ NOT_FOUND_MESSAGE == "Not Found" ]
  then
    echo "branch $CIRCLE_BRANCH does not exists in content-test-conf repo - downloading from master"

    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json" -o conf.json

    echo "END"
    cat ./conf.json
    echo "#################"
fi

echo "Successfully downloaded configuration file"
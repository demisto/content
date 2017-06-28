# download configuration file from github repo

echo "Getting conf from branch $CIRCLE_BRANCH (fallback to master)"

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json?ref=$CIRCLE_BRANCH" -o conf.json

NOT_FOUND_MESSAGE=$(cat ./conf.json | jq '.message')

if [ ! -z NOT_FOUND_MESSAGE ]
  then
    echo "Branch $CIRCLE_BRANCH does not exists in content-test-conf repo - downloading from master"
    echo "Got message from github=$NOT_FOUND_MESSAGE"

    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json" -o conf.json
fi

echo "Successfully downloaded configuration file"
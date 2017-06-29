# download configuration file from github repo

echo "Getting conf from branch $CIRCLE_BRANCH (fallback to master)"

CONF_PATH="./conf.json"
echo CONF_PATH > conf_path

curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json?ref=$CIRCLE_BRANCH" -o "$CONF_PATH"

NOT_FOUND_MESSAGE=$(cat ./conf.json | jq '.message')

if [ ! -z NOT_FOUND_MESSAGE ]
  then
    echo "Branch $CIRCLE_BRANCH does not exists in content-test-conf repo - downloading from master"
    echo "Got message from github=$NOT_FOUND_MESSAGE"

    curl  --header "Accept: application/vnd.github.v3.raw" --header "Authorization: token $GITHUB_TOKEN"  \
      --location "https://api.github.com/repos/demisto/content-test-conf/contents/conf.json" -o "$CONF_PATH"
fi

cat "$CONF_PATH"

echo "####"

cat ./conf.json

echo "Successfully downloaded configuration file"
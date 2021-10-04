echo 'export CI_BUILD_ID="$CIRCLE_BUILD_NUM"' >> $BASH_ENV
echo 'export CI_PIPELINE_ID="$CIRCLE_WORKFLOW_ID"' >> $BASH_ENV
echo 'export CI_COMMIT_BRANCH="$CIRCLE_BRANCH"' >> $BASH_ENV
echo 'export ARTIFACTS_FOLDER=/home/circleci/project/artifacts' >> $BASH_ENV
echo 'export CI_COMMIT_SHA="$CIRCLE_SHA1"' >> $BASH_ENV
echo 'export CI_JOB_URL="$CIRCLE_BUILD_URL"' >> $BASH_ENV
echo 'export CI_JOB_NAME="$CIRCLE_JOB"' >> $BASH_ENV
if [[ ! -f "$GCS_ARTIFACTS_KEY" ]];
then
  GCS_ARTIFACTS_PATH=$(mktemp)
  echo "$GCS_ARTIFACTS_KEY" > "$GCS_ARTIFACTS_PATH"
  echo "export GCS_ARTIFACTS_KEY=$GCS_ARTIFACTS_PATH" >> $BASH_ENV
fi

if [[ ! -f "$GCS_MARKET_KEY" ]];
then
  GCS_MARKET_PATH=$(mktemp)
  echo "$GCS_MARKET_KEY" > "$GCS_MARKET_PATH"
  echo "export GCS_MARKET_KEY=$GCS_MARKET_PATH" >> $BASH_ENV
fi

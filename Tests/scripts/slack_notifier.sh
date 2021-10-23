#!/usr/bin/env bash

echo "start slack notifier"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${BUCKET_UPLOAD}" ] && IS_BUCKET_UPLOAD=true || IS_BUCKET_UPLOAD=false

# $1 = test_type - unittests | test_playbooks | sdk_unittests | sdk_failed_steps | bucket_upload |
# $2 = env_results_file_name
# $3 = Slack channel

if [ "$CIRCLECI" != "true" ]; then
  python3 ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -u "$CI_JOB_URL" -b "$CI_JOB_ID" -s "$SLACK_TOKEN" -c "$GITLAB_STATUS_TOKEN" -t "$1" -f "$2" -bu $IS_BUCKET_UPLOAD -j "$CI_JOB_NAME" -ca "$ARTIFACTS_FOLDER" -ch "$3" -g "$CI_SERVER_URL" -gp "$CI_PROJECT_ID"
else
  python3 ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -u "$CIRCLE_BUILD_URL" -b "$CIRCLE_BUILD_NUM" -s "$SLACK_TOKEN" -c "$CIRCLECI_TOKEN" -t "$1" -f "$2" -bu $IS_BUCKET_UPLOAD -j "$CIRCLE_JOB" -ca $CIRCLE_ARTIFACTS -ch "$3"
fi

echo "Finished slack notifier execution"
#!/usr/bin/env bash

echo "start slack notifier"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${BUCKET_UPLOAD}" ] && IS_BUCKET_UPLOAD=true || IS_BUCKET_UPLOAD=false

if [ -n "$3" ]; then
  echo "$3"
  python3 ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -u "$CIRCLE_BUILD_URL" -b "$CIRCLE_BUILD_NUM" -s "$SLACK_TOKEN" -c "$CIRCLECI_TOKEN" -t $1 -f $2 -bu $IS_BUCKET_UPLOAD -j "$3"
else
  python3 ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -u "$CIRCLE_BUILD_URL" -b "$CIRCLE_BUILD_NUM" -s "$SLACK_TOKEN" -c "$CIRCLECI_TOKEN" -t $1 -f $2 -bu $IS_BUCKET_UPLOAD
fi

echo "Finished slack notifier execution"

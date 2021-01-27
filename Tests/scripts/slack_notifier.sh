#!/usr/bin/env bash

echo "start slack notifier"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${BUCKET_UPLOAD}" ] && IS_BUCKET_UPLOAD=true || IS_BUCKET_UPLOAD=false

python3 ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -u "$CIRCLE_BUILD_URL" -b "$CIRCLE_BUILD_NUM" -s "$SLACK_TOKEN" -c "$CIRCLECI_TOKEN" -t $1 -f "$2" -bu $IS_BUCKET_UPLOAD -j "$CIRCLE_JOB" -ca $CIRCLE_ARTIFACTS

echo "Finished slack notifier execution"

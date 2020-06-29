#!/usr/bin/env bash

echo "start slack notifier"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${DEMISTO_SDK_NIGHTLY}" ] && DEMISTO_SDK_NIGHTLY=true || DEMISTO_SDK_NIGHTLY=false

python3 ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -k $DEMISTO_SDK_NIGHTLY -u "$CIRCLE_BUILD_URL" -b "$CIRCLE_BUILD_NUM" -s "$SLACK_TOKEN" -c "$CIRCLECI_TOKEN" -i $1 -f $2

echo "Finished slack notifier execution"

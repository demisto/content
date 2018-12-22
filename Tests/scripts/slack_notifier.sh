#!/usr/bin/env bash

echo "start slack notifier"

python ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -u "$CIRCLE_BUILD_URL" -b "$CIRCLE_BUILD_NUM" -s "$SLACK_TOKEN" -c "$CIRCLECI_TOKEN"

echo "Finished slack notifier execution"

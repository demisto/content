#!/usr/bin/env bash

echo "start slack notifier"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false

<<<<<<< HEAD
python ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -u "$CIRCLE_BUILD_URL" -b "$CIRCLE_BUILD_NUM" -s "$SLACK_TOKEN" -c "$CIRCLECI_TOKEN" -f $1
=======
python ./Tests/scripts/slack_notifier.py -n $IS_NIGHTLY -u "$CIRCLE_BUILD_URL" -b "$CIRCLE_BUILD_NUM" -s "$SLACK_TOKEN" -c "$CIRCLECI_TOKEN" -i $1 -f $2
>>>>>>> upstream/master

echo "Finished slack notifier execution"

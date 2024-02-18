#!/usr/bin/env bash


_slack_channel="dmst-build-test"

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--ci-token) _ci_token="$2"
    shift
    shift;;

  -sdk|--sdk-ref) _sdk_ref="$2"
    shift
    shift;;

  -ch|--slack-channel) _slack_channel="$2"
    shift
    shift;;

  esac
done

if [ -z "$_ci_token" ]; then
    echo "You must provide a ci token."
    exit 1
fi

GOLD_PROJECT_ID=${GOLD_PROJECT_ID:-1738}
CI_SERVER_URL=${CI_SERVER_URL:-https://gitlab.xdr.pan.local} # disable-secrets-detection

export BUILD_TRIGGER_URL="${CI_SERVER_URL}/api/v4/projects/${GOLD_PROJECT_ID}/trigger/pipeline"


curl --request POST \
  --form "ref=master" \
  --form "token=${_ci_token}" \
  --form "variables[SDK_REF]=${_sdk_ref}" \
  --form "variables[NIGHTLY]=true" \
  --form "variables[SLACK_CHANNEL]=${_slack_channel}" \
  "$BUILD_TRIGGER_URL"

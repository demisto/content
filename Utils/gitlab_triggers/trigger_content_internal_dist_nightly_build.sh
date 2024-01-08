#!/usr/bin/env bash



while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--ci-token) _ci_token="$2"
    shift
    shift;;

  -sdk|--sdk-ref) _sdk_ref="$2"
    shift
    shift;;

  esac
done

if [ -z "$_ci_token" ]; then
    echo "You must provide a ci token."
    exit 1
fi

export BUILD_TRIGGER_URL="https://gitlab.xdr.pan.local/api/v4/projects/1738/trigger/pipeline"


curl --request POST \
  --form "ref=master" \
  --form "token=${_ci_token}" \
  --form "variables[SDK_REF]=${_sdk_ref}" \
  --form "variables[NIGHTLY]=true" \
  --form "variables[SLACK_CHANNEL]=C05FPQR3WHK" \
  "$BUILD_TRIGGER_URL"

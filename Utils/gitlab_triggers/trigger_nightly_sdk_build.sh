#!/usr/bin/env bash
# This script triggers a nightly job in gitlab-CI.

# For this script to work you will need to use a trigger token (see here for more about that: https://code.pan.run/help/ci/triggers/README#trigger-token)  # disable-secrets-detection

# This script requires the gitlab-ci trigger token.

# The branch to run against is an optional second parameter (the default is the current branch).
# The slack channel to send messages to is an optional third parameter (the default is the 'dmst-content-team')
# the sdk-ref is the demisto-sdk branch name.


if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>
  -ct, --ci-token             The ci token.
  [-b, --branch]              The content repo branch name. Default is the current branch.
  [-ch, --slack-channel]      A slack channel to send notifications to. Default is dmst-bucket-upload.
  [-sr, --sdk-ref]            The demisto-sdk repo branch to run this build with.
  "

  echo "Get the trigger token from here https://vault.paloaltonetworks.local/home#R2VuZXJpY1NlY3JldERldGFpbHM6RGF0YVZhdWx0OmIyMzJiNDU0LWEzOWMtNGY5YS1hMTY1LTQ4YjRlYzM1OTUxMzpSZWNvcmRJbmRleDowOklzVHJ1bmNhdGVk" # disable-secrets-detection
  exit 1
fi
_branch="$(git branch  --show-current)"
_sdk_ref="master"

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--ci-token) _ci_token="$2"
    shift
    shift;;

  -b|--branch) _branch="$2"
    shift
    shift;;

  -ch|--slack-channel) _slack_channel="$2"
    shift
    shift;;

  -sr|--sdk-ref) _sdk_ref="$2"
    shift
    shift;;


  *)    # unknown option.
    shift;;
  esac
done

if [ -z "$_ci_token" ]; then
    echo "You must provide a ci token."
    exit 1
fi

_variables="variables[DEMISTO_SDK_NIGHTLY]=true"

source Utils/gitlab_triggers/trigger_build_url.sh

curl --request POST \
  --form token="${_ci_token}" \
  --form ref="${_branch}" \
  --form "${_variables}" \
  --form "variables[SLACK_CHANNEL]=${_slack_channel}" \
  --form "variables[SDK_REF]=${_sdk_ref}" \
  "$BUILD_TRIGGER_URL"


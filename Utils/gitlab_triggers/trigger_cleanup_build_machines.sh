#!/usr/bin/env bash
# This script triggers a cleanup build machines job in gitlab-CI.

# For this script to work you will need to use a trigger token (see here for more about that: https://code.pan.run/help/ci/triggers/README#trigger-token)  # disable-secrets-detection

# This script requires the gitlab-ci trigger token. The branch to run against is an optional second parameter
# (the default is the current branch). The Slack channel to send messages to is an optional
# third parameter (the default is the 'dmst-build-test')

# Ways to run this script are:
# trigger_content_nightly_build.sh -ct <trigger-token> [-b <branch-name> -ch <slack-channel-name>]
if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>

  [-ct, --ci-token]      The ci gitlab trigger token.
  [-b, --branch]         The branch name. Default is the current branch.
  [-ch, --slack-channel] A Slack channel to send notifications to. Default is dmst-build-test.
  "
  echo "Get the trigger token from here https://vault.paloaltonetworks.local/home#R2VuZXJpY1NlY3JldERldGFpbHM6RGF0YVZhdWx0OmIyMzJiNDU0LWEzOWMtNGY5YS1hMTY1LTQ4YjRlYzM1OTUxMzpSZWNvcmRJbmRleDowOklzVHJ1bmNhdGVk" # disable-secrets-detection
  exit 1
fi

_branch="$(git branch  --show-current)"
_slack_channel="dmst-build-test"

# Parsing the user inputs.

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

  *)    # unknown option.
    shift;;
  esac
done

if [ -z "$_ci_token" ]; then
    echo "You must provide a ci token."
    exit 1
fi

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${SCRIPT_DIR}/trigger_build_url.sh"

curl "$BUILD_TRIGGER_URL" --form "ref=${_branch}" --form "token=${_ci_token}" \
    --form "variables[BUILD_MACHINES_CLEANUP]=true" \
    --form "variables[SLACK_CHANNEL]=${_slack_channel}"  | jq

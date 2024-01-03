#!/usr/bin/env bash
# This script triggers Demisto SDK release job in gitlab-CI.

# For this script to work you will need to use a trigger token (see here for more about that: https://docs.gitlab.com/ee/ci/triggers/#create-a-pipeline-trigger-token)

# This script requires the gitlab-ci trigger token and release version.
# The branch to run against is an optional parameter(the default is master branch).
# The Slack channel to send messages to is an optional parameter(the default is dmst-sdk-release).

# Ways to run this script are:
# trigger_demisto_sdk_release.sh -ct <trigger-token> -rv <release-version> [-b <branch-name> -ch <slack-channel-name>]
if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>

  [-ct, --ci-token]      The ci gitlab trigger token.
  [-rv, --release-version]      The release version.
  [-ch, --slack-channel] A Slack channel to send notifications to. Default is dmst-sdk-release.
  [-b, --branch]         The branch name. Default is master branch.
  "
  echo "Get the trigger token from here https://vault.paloaltonetworks.local/home#R2VuZXJpY1NlY3JldERldGFpbHM6RGF0YVZhdWx0OmIyMzJiNDU0LWEzOWMtNGY5YS1hMTY1LTQ4YjRlYzM1OTUxMzpSZWNvcmRJbmRleDowOklzVHJ1bmNhdGVk" # disable-secrets-detection  TODO
  exit 1
fi

_branch="master"
_slack_channel="dmst-sdk-release"

# Parsing the user inputs.

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--ci-token) _ci_token="$2"
    shift
    shift;;

  -rv|--release-version) _release_versionZ="$2"
    shift
    shift;;

  -b|--branch) _branch="$2"
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

if [ -z "$_release_version" ]; then
    echo "You must provide a release version."
    exit 1
fi


echo "ci_token=" $_ci_token
echo "slack_channel=" $_slack_channel
echo "branch=" $_branch
echo "release_version=" $_release_version

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${SCRIPT_DIR}/trigger_build_url.sh"

curl "$BUILD_TRIGGER_URL" --form "ref=${_branch}" --form "token=${_ci_token}" \
    --form "variables[SDK_RELEASE]=true" \
    --form "variables[BRANCH_NAME]=${_branch}" \
    --form "variables[RELEASE_VERSION]=${_release_version}" \
    --form "variables[SLACK_CHANNEL]=${_slack_channel}"  | jq
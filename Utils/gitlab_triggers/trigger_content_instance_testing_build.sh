c# !/usr/bin/env bash
# This script triggers an instance-testing job in gitlab-CI.

# For this script to work you will need to use a trigger token (see here for more about that: https://code.pan.run/help/ci/triggers/README#trigger-token)  # disable-secrets-detection

# This script takes the gitlab-ci trigger token as first parameter and the branch name as an optional second parameter (the default is the current branch).

# Ways to run this script are:
# 1. Utils/gitlab_triggers/trigger_content_nightly_build.sh <trigger-token> <branch-name>
# 2. Utils/gitlab_triggers/trigger_content_nightly_build.sh <trigger-token>
if [[ "$#" -lt 1 ]]; then
  echo "Usage: $0 <trigger-token> <branch-name>[current-branch as default]"
  echo "Get the trigger token from here https://vault.paloaltonetworks.local/home#R2VuZXJpY1NlY3JldERldGFpbHM6RGF0YVZhdWx0OmIyMzJiNDU0LWEzOWMtNGY5YS1hMTY1LTQ4YjRlYzM1OTUxMzpSZWNvcmRJbmRleDowOklzVHJ1bmNhdGVk" # disable-secrets-detection
  exit 1
fi
_gitlab_token=$1

[ -n "$2" ] && _branch="$2" || _branch="$(git branch  --show-current)"

source Utils/gitlab_triggers/trigger_build_url.sh

curl "$BUILD_TRIGGER_URL" -F "ref=$_branch" -F "token=$_gitlab_token" -F "variables[INSTANCE_TESTS]=true" -F "variables[IFRA_ENV_TYPE]=Server 5.5" | jq

#!/usr/bin/env bash


if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>
  -ct, --ci-token             The ci token.
  [-b, --branch]              The content repo branch name. Default is the current branch.
  [-g, --gitlab]              Flag to pass if triggering a build in GitLab
  [-ch, --slack-channel]      A slack channel to send notifications to. Default is dmst-bucket-upload.
  [-sr, --sdk-ref]            The demisto-sdk repo branch to run this build with.
  "
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

  -g|--gitlab) _gitlab=true
    shift;;

  *)    # unknown option.
    shift;;
  esac
done

if [ -z "$_ci_token" ]; then
    echo "You must provide a ci token."
    exit 1
fi

if [ -n "$_gitlab" ]; then

  _variables="variables[DEMISTO_SDK_NIGHTLY]=true"

  source Utils/gitlab_triggers/trigger_build_url.sh

  curl --request POST \
    --form token="${_ci_token}" \
    --form ref="${_branch}" \
    --form "${_variables}" \
    --form "variables[SLACK_CHANNEL]=${_slack_channel}" \
    --form "variables[SDK_REF]=${_sdk_ref}" \
    "$BUILD_TRIGGER_URL"

else
  trigger_build_url="https://circleci.com/api/v2/project/github/demisto/content/pipeline"

  post_data=$(cat <<-EOF
  {
    "branch": "${_branch}",
    "parameters": {
      "demisto_sdk_nightly": "true",
      "sdk_ref": "${_sdk_ref}"
    }
  }
EOF
)

  curl \
  --header "Accept: application/json" \
  --header "Content-Type: application/json" \
  -k \
  --data "${post_data}" \
  --request POST ${trigger_build_url} \
  --user "$_ci_token:"
fi

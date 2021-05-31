#!/usr/bin/env bash

if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>

  -ct, --circle-token         The circleci token.
  [-b, --branch]              The branch name. Default is the current branch.
  [-gb, --bucket]             The name of the bucket to upload the packs to. Default is marketplace-dist-dev.
  [-f, --force]               Whether to trigger the force upload flow.
  [-p, --packs]               CSV list of pack IDs. Mandatory when the --force flag is on.
  [-ch, --slack-channel]      A slack channel to send notifications to. Default is dmst-bucket-upload.
  "
  exit 1
fi

_branch="$(git branch  --show-current)"
_bucket="marketplace-dist-dev"
_bucket_upload="true"
_slack_channel="dmst-bucket-upload"

# Parsing the user inputs.

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--circle-token) _circle_token="$2"
    shift
    shift;;

  -b|--branch) _branch="$2"
    shift
    shift;;

  -gb|--bucket)
  if [ "$(echo "$2" | tr '[:upper:]' '[:lower:]')" == "marketplace-dist" ]; then
    echo "Only test buckets are allowed to use. Using marketplace-dist-dev instead."
  else
    _bucket=$2
  fi
    shift
    shift;;

  -f|--force) _force=true
    _bucket_upload=""
    shift;;

  -p|--packs) _packs="$2"
    shift
    shift;;

  -ch|--slack-channel) _slack_channel="$2"
    shift
    shift;;

  *)    # unknown option.
    shift;;
  esac
done


if [ -z "$_circle_token" ]; then
    echo "You must provide a circle token."
    exit 1
fi

if [ -n "$_force" ] && [ -z "$_packs" ]; then
    echo "You must provide a csv list of packs to force upload."
    exit 1
fi


trigger_build_url="https://circleci.com/api/v2/project/github/demisto/content/pipeline"

post_data=$(cat <<-EOF
{
  "branch": "${_branch}",
  "parameters": {
    "gcs_market_bucket": "${_bucket}",
    "bucket_upload": "${_bucket_upload}",
    "force_pack_upload": "${_force}",
    "packs_to_upload": "${_packs}",
    "slack_channel": "${_slack_channel}"
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
--user "$_circle_token:"

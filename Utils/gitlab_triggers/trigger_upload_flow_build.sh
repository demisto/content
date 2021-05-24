#!/usr/bin/env bash

if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>

  -ct, --ci-token             The ci gitlab token.
  [-b, --branch]              The branch name. Default is the current branch.
  [-gb, --bucket]             The name of the bucket to upload the packs to. Default is marketplace-dist-dev.
  [-f, --force]               Whether to trigger the force upload flow.
  [-p, --packs]               CSV list of pack IDs. Mandatory when the --force flag is on.
  [-ch, --slack-channel]      A slack channel to send notifications to. Default is dmst-bucket-upload.
  "
  exit 1
fi

branch="$(git branch  --show-current)"
_bucket="marketplace-dist-dev"
_bucket_upload="true"
_slack_channel="dmst-bucket-upload"

# Parsing the user inputs.

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--ci-token) _ci_token="$2"
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


if [ -z "$_ci_token" ]; then
    echo "You must provide a ci token."
    exit 1
fi

if [ -n "$_force" ] && [ -z "$_packs" ]; then
    echo "You must provide a csv list of packs to force upload."
    exit 1
fi

source Utils/gitlab_triggers/trigger_build_url.sh

_variables="variables[BUCKET_UPLOAD]=true"
if [ -n "$_force" ]; then
  _variables="variables[FORCE_BUCKET_UPLOAD]=true"
fi

source Utils/gitlab_triggers/trigger_build_url.sh

curl --request POST \
  --form token="${_ci_token}" \
  --form ref="${_branch}" \
  --form "${_variables}" \
  --form "variables[SLACK_CHANNEL]=${_slack_channel}" \
  --form "variables[PACKS_TO_UPLOAD]=${_packs}" \
  --form "variables[GCS_MARKET_BUCKET]=${_bucket}" \
  --form "variables[IFRA_ENV_TYPE]=Bucket-Upload" \
  "$BUILD_TRIGGER_URL"

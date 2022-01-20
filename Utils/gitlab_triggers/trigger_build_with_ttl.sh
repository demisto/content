#!/usr/bin/env bash

if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>

  -ct, --ci-token             The ci gitlab token.
  [-ttl, --time-to-live]      The time to live in minutes.
  [-b, --branch]              The branch name. Default is the current branch.
  "
  exit 1
fi

_branch="$(git branch  --show-current)"
_ttl=300

# Parsing the user inputs.

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--ci-token) _ci_token="$2"
    shift
    shift;;

  -b|--branch) _branch="$2"
    shift
    shift;;

  -ttl|--time-to-live) _ttl="$2"
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

source Utils/gitlab_triggers/trigger_build_url.sh

curl -k --request POST \
  --form token="${_ci_token}" \
  --form ref="${_branch}" \
  --form "variables[TIME_TO_LIVE]=${_ttl}" \
  --form "variables[CI_PIPELINE_SOURCE]=push" \
  "$BUILD_TRIGGER_URL" | jq

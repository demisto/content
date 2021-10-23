#!/usr/bin/env bash

if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token> -b <branch>
  [-ct, --ci-token]           The ci token.
  [-b, --branch]              The content repo branch name. Default is the current branch.
  [-l, --legacy]              Flag to pass if triggering a legacy nightly build (aka running all test playbooks)
  "
  exit 1
fi

_branch="$(git branch  --show-current)"
_nightly_type="nightly"

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--ci-token) _ci_token="$2"
    shift
    shift;;

  -b|--branch) _branch="$2"
    shift
    shift;;

  -l|--legacy) _nightly_type="legacy_nightly"
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

trigger_build_url="https://circleci.com/api/v2/project/github/demisto/content/pipeline"

post_data=$(cat <<-EOF
{
  "branch": "${_branch}",
  "parameters": {
    "${_nightly_type}": "true",
    "time_to_live": "900"
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

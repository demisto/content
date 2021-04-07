#!/usr/bin/env bash

_circle_token=$1
[ -n "$2" ] && _branch="$2" || _branch="$(git branch  --show-current)"

trigger_build_url="https://circleci.com/api/v2/project/github/demisto/content/pipeline"

post_data=$(cat <<-EOF
{
  "branch": "${_branch}",
  "parameters": {
    "nightly": "true",
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
--user "$_circle_token:"

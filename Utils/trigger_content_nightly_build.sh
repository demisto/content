#!/usr/bin/env bash

_branch=$1
_circle_token=$2

trigger_build_url=https://circleci.com/api/v1/project/demisto/content/tree/${_branch}?circle-token=${_circle_token}

post_data=$(cat <<EOF
{
  "build_parameters": {
    "NIGHTLY": "true"
  }
}
EOF)

curl \
--header "Accept: application/json" \
--header "Content-Type: application/json" \
--data "${post_data}" \
--request POST ${trigger_build_url}
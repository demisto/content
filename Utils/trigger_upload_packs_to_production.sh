#!/usr/bin/env bash

if [ "$#" -ne "1" ]; then
  echo "invalid command line, expected: $0 <circle token>"
  exit 1
fi

_circle_token=$1

trigger_build_url="https://circleci.com/api/v2/project/github/demisto/content/pipeline"

post_data=$(cat <<-EOF
{
  "branch": "master",
  "parameters": {
    "bucket_upload": "true"
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

#!/usr/bin/env bash

if [[ "$#" -lt 2 ]]; then
  echo "Usage: $0 <content branch name: such as master> <circle ci token> [server branch name] [nightly: set to true or leave blank]"
  echo "You can get a circle ci token from: CircleCI -> User -> Personal API Tokens"
  echo "Note: if doing a nightly build you must specify server branch name"
  exit 1
fi

_branch=$1
_circle_token=$2

trigger_build_url="https://circleci.com/api/v2/project/github/demisto/content/pipeline"

if [ -z "$3" ]; then
  post_data=$(cat <<-EOF
 {
    "branch": "${_branch}",
    "parameters": {
      "non_ami_run": "true"
    }
  }
EOF
)
else
  post_data=$(cat <<-EOF
  {
    "branch": "${_branch}",
    "parameters": {
      "non_ami_run": "true",
      "artifact_build_num": "$3",
      "nightly": "true"
    }
  }
EOF
)
fi

echo "Going to post to: $trigger_build_url the following data:"
echo "$post_data"

curl \
--header "Accept: application/json" \
--header "Content-Type: application/json" \
-k \
--data "${post_data}" \
--request POST ${trigger_build_url} \
--user "$_circle_token:"

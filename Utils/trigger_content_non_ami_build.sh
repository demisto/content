#!/usr/bin/env bash

if [[ "$#" -lt 2 ]]; then
  echo "Usage: $0 <content branch name: such as master> <circle ci token> [server branch name] [nightly: set to true or leave blank]"
  echo "You can get a circle ci token from: CircleCI -> User -> Personal API Tokens"
  echo "Note: if doiong a nightly build you must specify server branch name"
  exit 1
fi

_branch=$1
_circle_token=$2

trigger_build_url="https://circleci.com/api/v1/project/demisto/content/tree/${_branch}?circle-token=${_circle_token}"

if [ -z "$3" ]; then
  post_data=$(cat <<-EOF
  {
    "build_parameters": {
      "NON_AMI_RUN": "true"
    }
  }
EOF
)
else
  post_data=$(cat <<-EOF
  {
    "build_parameters": {
      "NON_AMI_RUN": "true",
      "SERVER_BRANCH_NAME": "$3",
      "NIGHTLY": "$4"
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
--data "${post_data}" \
--request POST ${trigger_build_url}

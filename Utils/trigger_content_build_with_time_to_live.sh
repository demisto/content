#!/usr/bin/env bash

if [[ "$#" -lt 2 ]]; then
  echo "Usage: $0 <content branch name: such as master> <circle ci token> [contributor branch name] [minutes to live]"
  echo "You can get a circle ci token from: CircleCI -> User -> Personal API Tokens"
  echo "Time to live is in minutes, for example 360 equals 6 hours for the instance to live"
  echo "Defualt time to live is 360 minutes"
  exit 1
fi

_branch=$1
_circle_token=$2
_time_to_live=$3

if [ -z "$_time_to_live" ]
then
      _time_to_live="360"
fi


trigger_build_url=https://circleci.com/api/v1/project/demisto/content/tree/${_branch}?circle-token=${_circle_token}

post_data=$(cat <<EOF
{
  "build_parameters": {
    "TIME_TO_LIVE": ${_time_to_live}
  }
}
EOF)

curl \
--header "Accept: application/json" \
--header "Content-Type: application/json" \
--data "${post_data}" \
--request POST ${trigger_build_url}
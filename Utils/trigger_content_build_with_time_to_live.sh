#!/usr/bin/env bash

if [[ "$#" -lt 2 ]]; then
  echo "Usage: $0 <content branch name: such as master> <circle ci token> [contributor branch name] [minutes to live]"
  echo "You can get a circle ci token from: CircleCI -> User -> Personal API Tokens"
  echo "Time to live is in minutes, for example 360 equals 6 hours for the instance to live"
  echo "Minmum time to live is 180 minutes, maximum time is 540 minutes"
  echo "If time to live not entered the defualt will be 180 minutes"
  exit 1
fi

_branch=$1
_circle_token=$2
_time_to_live=$3

if [ -z $_time_to_live ] || [ $_time_to_live -lt 180 ]
then
      echo "Minumum time is 180 minutes. The script will use defualt time to live"
      _time_to_live=180
fi

if [ $_time_to_live -gt 540 ]
then
    echo "Maximum time is 540 minutes, please change the time_to_live argument"
    exit 1
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
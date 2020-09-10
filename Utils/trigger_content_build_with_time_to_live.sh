#!/usr/bin/env bash

# There are two use-cases to use this script:
# 1. Running the script on local branch
# The script will get local_branch_name, circleCi token and time_to_live argument (in minutes) and set the instances in the build according to the given time.
# For example:
# ./Utils/trigger_content_build_with_time_to_live.sh my_branch_name <CircleCi token> 360
# After running this command line  it will trigger a build on the given branch and all of the instances will live for 6 hours.
# in this case, if you don’t specify time to live argument the default will be 180 minutes.

# 2. Running the script with the contributor changes
# The script will get local_branch_name, circleCi token, time to live argument(in minutes), contributor_user_name:contributor_branch_name and the pack path of the pack that has been changed/added.
# For example:
# ./Utils/trigger_content_build_with_time_to_live.sh content_branch_name <CircleCiToken> 420 contrib_name:contrib_branch_name Packs/New_Pack/
# In this case, the script will trigger a build and the demisto-marketplace instance will live for 7 hours.
# Notice that if you want to run a build on contributor branch you must specify time to live argument and the recommended time is 180 minutes.

if [[ "$#" -lt 2 ]]; then
  echo "Usage: $0 <content branch name: such as master> <circle ci token> [time to live] [contributor branch: such as testUser:testBranch] [changed pack: such as Packs/test_pack/]"
  echo "You can get a circle ci token from: CircleCI -> User -> Personal API Tokens"
  echo "Time to live is in minutes, for example 360 equals 6 hours"
  echo "Minimum time to live is 180 minutes, maximum time is 540 minutes"
  echo "If time to live not entered the defualt will be 180 minutes"
  exit 1
fi

_branch=$1
_circle_token=$2
_time_to_live=$3
_contrib_branch=$4
_changed_pack=$5

trigger_build_url="https://circleci.com/api/v2/project/github/demisto/content/pipeline"


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

if [ -n "$_contrib_branch" ] && [ -z $_changed_pack ]
then
    echo "You must specify the pack name"
    exit 1
fi

if [ -z $_contrib_branch ]
then
  post_data=$(cat <<-EOF
 {
    "branch": "${_branch}",
    "parameters": {
      "time_to_live": "${_time_to_live}"
    }
  }
EOF
)

else
  pack_name=$(echo $_changed_pack | cut -d "/" -f 2)
  post_data=$(cat <<-EOF
 {
    "branch": "${_branch}",
    "parameters": {
      "time_to_live": "${_time_to_live}",
      "contrib_branch": "${_contrib_branch}:${_changed_pack}",
      "contrib_pack_name": "$pack_name"
    }
  }
EOF
)
fi

curl \
--header "Accept: application/json" \
--header "Content-Type: application/json" \
-k \
--data "${post_data}" \
--request POST ${trigger_build_url} \
--user "$_circle_token:"

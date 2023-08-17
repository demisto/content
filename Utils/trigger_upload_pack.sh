#!/usr/bin/env bash

if [ "$#" -lt "1" ]; then
  echo "Usage:
      $0 -ct <token>
      $0 -ct <token> -p <CSV list of pack IDs>

  -ct, --circle-token     The circleci token.
  [-p, --packs]           CSV list of pack IDs.
  "
  exit 1
fi

_bucket_upload="true"

# Parsing the user inputs.

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--circle-token) _circle_token="$2"
    shift
    shift;;

  -p|--packs) _packs="$2"
    shift
    shift;;

  *)    # unknown option.
    shift;;
  esac
done


if [ -z "$_circle_token" ]; then
    echo "You must provide a circle token."
    exit 1
fi

if [ -z "$_packs" ]; then
    echo "You must provide a csv list of packs."
    exit 1
fi

trigger_build_url="https://circleci.com/api/v2/project/github/demisto/content/pipeline"

post_data=$(cat <<-EOF
{
  "branch": "master",
  "parameters": {
    "bucket_upload": "${_bucket_upload}",
    "packs_to_upload": "${_packs}"
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

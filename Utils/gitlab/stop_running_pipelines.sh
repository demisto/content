#!/usr/bin/env bash

# exit on errors
set -e

# set local vars
CONTENT_PIPELINES_API_URL=https://code.pan.run/api/v4/projects/2596/pipelines # disable-secrets-detection

if [ -z "$1" ]; then
  echo "No commit branch. Aborting."
  exit 1
else
  CI_COMMIT_BRANCH=$1
fi

if [ -z "$2" ]; then
  echo "No pipeline number. Aborting."
  exit 1
else
  CI_PIPELINE_ID=$2
fi

# Helper functions

function get_branch_pipelines(){
  local resp=$1
  echo $(echo "${resp}" | jq -c '.[]')
}

function stop_pipeline_by_id(){
  curl --request POST --header "PRIVATE-TOKEN: $GITLAB_CANCEL_TOKEN" "$CONTENT_PIPELINES_API_URL/$1/cancel"
}

# Stopping pipelines
RESP=$(curl -v -H "Content-Type: application/json" -H "PRIVATE-TOKEN: $GITLAB_CANCEL_TOKEN" $CONTENT_PIPELINES_API_URL\?ref\=$CI_COMMIT_BRANCH)
if [ "$RESP" != "[]" ]; then
  PIPELINES=$(get_branch_pipelines "$RESP")
  for pipeline in ${PIPELINES}
  do
    source=$(echo $pipeline | jq -r ".source")
    status=$(echo $pipeline | jq -r ".status")
    id=$(echo $pipeline | jq -r ".id")
    if [ "$status" = "running" ] && [ "$source" = "push" ] && [ $CI_PIPELINE_ID -gt "$id" ]; then
      echo "Found running pipeline with id $id, and status $status. Stopping it."
      stop_pipeline_by_id "$id"
    fi
  done
fi

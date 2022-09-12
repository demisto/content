#!/usr/bin/env bash

GCS_MARKET_KEY=$1
ARTIFCATS_FOLDER=$2
GITLAB_TOKEN=$3
CURRENT_BRANCH=upload_testing_flow_upload_test_branch_1662986278.566966
#CURRENT_BRANCH=$(python3 ./Utils/test_upload_flow/create_test_branch.py -a $ARTIFCATS_FOLDER)
Sleep 5m
pipeline_id=echo ./Utils/trigger_test_upload_flow.sh -ct $GITLAB_TOKEN -g | jq .id
test_upload_storage_base_path=upload-flow/builds
current_storage_base_path="$test_upload_storage_base_path/$CURRENT_BRANCH/$pipeline_id/content/packs"
#Sleep 1h 30m
python3 ./Utils/test_upload_flow/verify_bucket.py -a $ARTIFCATS_FOLDER -s $GCS_MARKET_KEY -b 'marketplace-dist-dev' -sb $current_storage_base_path
python3 ./Utils/test_upload_flow/verify_bucket.py -a $ARTIFCATS_FOLDER -s $GCS_MARKET_KEY -b 'marketplace-v2-dist-dev' -sb $current_storage_base_path

#Left TODO:
#1. fix rule for job
#3. check how to both print logs and return final result in create_test_branch
#4. add image testing
#2. fix new pack not working

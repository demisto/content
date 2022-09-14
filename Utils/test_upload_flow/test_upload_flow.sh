#!/usr/bin/env bash
#
#GCS_MARKET_KEY=$1
#ARTIFCATS_FOLDER=$2
#GITLAB_TOKEN=$3
#CURRENT_BRANCH=upload_testing_flow_upload_test_branch_1662986278.566966
##CURRENT_BRANCH=$(python3 ./Utils/test_upload_flow/create_test_branch.py -a $ARTIFCATS_FOLDER)
#Sleep 5m
#pipeline_id=echo ./Utils/trigger_test_upload_flow.sh -ct $GITLAB_TOKEN -g | jq .id
#test_upload_storage_base_path=upload-flow/builds
#current_storage_base_path="$test_upload_storage_base_path/$CURRENT_BRANCH/$pipeline_id/content/packs"
##Sleep 1h 30m
#python3 ./Utils/test_upload_flow/verify_bucket.py -a $ARTIFCATS_FOLDER -s $GCS_MARKET_KEY -b 'marketplace-dist-dev' -sb $current_storage_base_path
#python3 ./Utils/test_upload_flow/verify_bucket.py -a $ARTIFCATS_FOLDER -s $GCS_MARKET_KEY -b 'marketplace-v2-dist-dev' -sb $current_storage_base_path

#Left TODO:
#1. fix rule for job - done
#3. check how to both print logs and return final result in create_test_branch - done
#4. add image testing - done
#2. fix new pack not working - done
#5. add all content items to new packs - done
#6. add push to gitlab
#7. add poilling on pipeline - done

if (git diff origin/master upload_testing_flow --name-only | grep "Tests/\|Utils/"); then                                                                            16:33:03
        section_start "Create Testing Branch"
        python3 ./Utils/test_upload_flow/create_test_branch.py -a $ARTIFACTS_FOLDER | tee "$ARTIFACTS_FOLDER/create_test_branch.log"
        section_end "Create Testing Branch"
        section_start "Wait For GitLab Mirroring"
        Sleep 5m # TODO: push to gitlab push to new remote in gitlab instead of origin
        section_end "Wait For GitLab Mirroring"
        section_start "Trigger Test Upload Flow On Testing Branch"
        branch="$ARTIFACTS_FOLDER/create_test_branch.log" tail -n 1
        pipeline_id=echo ./Utils/trigger_test_upload_flow.sh -ct $GITLAB_TOKEN -g | jq .id
        section_end "Trigger Test Upload Flow On Testing Branch"
        section_start "Wait For Upload To Finish"
        python3 ./Utils/wait_for_upload.py -p $pipeline_id -g $GITLAB_API_TOKEN
        section_end "Wait For Upload To Finish"
        section_start "Verify Created Testing Bucket"
        test_upload_storage_base_path=upload-flow/builds
        current_storage_base_path="$test_upload_storage_base_path/$branch/$pipeline_id/content/packs"
        python3 ./Utils/test_upload_flow/verify_bucket.py -a $ARTIFACTS_FOLDER -s $GCS_MARKET_KEY -b 'marketplace-dist-dev' -sb $current_storage_base_path
        python3 ./Utils/test_upload_flow/verify_bucket.py -a $ARTIFACTS_FOLDER -s $GCS_MARKET_KEY -b 'marketplace-v2-dist-dev' -sb $current_storage_base_path
        section_end "Verify Created Testing Bucket"
else
  echo "No upload related files were modified, skipping upload test."
  exit 0
fi
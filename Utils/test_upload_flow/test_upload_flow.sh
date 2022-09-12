GCS_MARKET_KEY=$1
ARTIFCATS_FOLDER=$2
GITLAB_TOKEN=$3
python3 ./Utils/test_upload_flow/create_test_branch.py -a ARTIFCATS_FOLDER
python3 ./Utils/trigger_test_upload_flow.sh -ct GITLAB_TOKEN -g
python3 ./Utils/test_upload_flow/verify_bucket.py -a ARTIFCATS_FOLDER -
#!/usr/bin/env bash
set -e

echo "Start create_instance script"

#configure aws
aws configure set region us-west-2

CONFFILE=$1

#Get nightly image of the server
IMAGE_ID=$(aws ec2 describe-images \
    --filters Name=name,Values=Demisto-Circle-CI-Content-Master* \
    --query 'Images[*].[ImageId,CreationDate]' --output text | sort -k2 -r | head -n1)

echo $IMAGE_ID > image_id.txt

python ./Tests/scripts/update_image_id.py -i image_id.txt -c $CONFFILE

#create instance
REQUEST_ID=$(aws ec2 request-spot-instances \
    --launch-specification file://${CONFFILE} \
    --query 'SpotInstanceRequests[0].SpotInstanceRequestId' | tr -d '"')

if [ -z "$REQUEST_ID" ]
then
    echo "Failed setting up request for spot-instance."
    exit 1
fi

MACHINE_STATE=""
TRY_COUNT=1
MAX_TRIES=10
MACHINE_STATE=$(aws ec2 describe-spot-instance-requests --spot-instance-request-ids "$REQUEST_ID" \
    --query 'SpotInstanceRequests[0].Status.Code' | tr -d '"')
while [ "$MACHINE_STATE" != "fulfilled" ] && [[ $TRY_COUNT -le $MAX_TRIES ]]; do
    echo "Waiting for machine to be ready ($REQUEST_ID). try # $TRY_COUNT"
    sleep 10
    MACHINE_STATE=$(aws ec2 describe-spot-instance-requests --spot-instance-request-ids "$REQUEST_ID" \
        --query 'SpotInstanceRequests[0].Status.Code' | tr -d '"')
    ((TRY_COUNT++))
done

INSTANCE_ID=""
if [ "$MACHINE_STATE" == "fulfilled" ]
then
    INSTANCE_ID=$(aws ec2 describe-spot-instance-requests --spot-instance-request-ids "$REQUEST_ID" \
        --query 'SpotInstanceRequests[0].InstanceId' | tr -d '"')
    echo "setup $INSTANCE_ID, changing name and stopping request."
    aws ec2 cancel-spot-instance-requests --spot-instance-request-ids "$REQUEST_ID"
    aws ec2 create-tags --resources $INSTANCE_ID --tags "Key=Name,Value=ContentBuildN${CIRCLE_BUILD_NUM}"
fi

if [ -z ${INSTANCE_ID} ]
then
    echo "Instance failed to start"
    exit 1
fi

echo "Instance ID is: $INSTANCE_ID"
echo ${INSTANCE_ID} > instance_ids

#!/usr/bin/env bash
set -e

if ! ./scripts/is_remote.sh ; then exit 0 ; fi

#configure aws
aws configure set region us-west-2

IMAGE_ID="ami-d2c924b2" # centos
if [ $CIRCLE_NODE_INDEX -eq 0 ]; then IMAGE_ID="ami-775e4f16"; fi # RHEL
if [ $CIRCLE_NODE_INDEX -eq 1 ]; then IMAGE_ID="ami-a58d0dc5"; fi # ubuntu 16

#create instance
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id ${IMAGE_ID} \
    --security-group-ids sg-714f3816 \
    --instance-type t2.micro \
    --key-name ci-key \
    --instance-initiated-shutdown-behavior terminate \
    --block-device-mappings DeviceName=/dev/sda1,Ebs={DeleteOnTermination=true} \
    --user-data file://scripts/aws/shutdown_instance.sh \
    --query 'Instances[0].InstanceId' | tr -d '"')

if [ -z ${INSTANCE_ID} ]
then
    echo "Instance failed to start"
    exit 1
fi

echo "Instance ID is: $INSTANCE_ID"
echo ${INSTANCE_ID} > instance_ids

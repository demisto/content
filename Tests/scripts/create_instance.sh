#!/usr/bin/env bash
set -e

echo "Start create_instance script"

#configure aws
aws configure set region us-west-2

echo "after configure"

IMAGE_ID="ami-d2c924b2" # centos

#create instance
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id ${IMAGE_ID} \
    --security-group-ids sg-714f3816 \
    --instance-type t2.micro \
    --key-name ci-key \
    --tags Key=Name,Value=Content-test \
    --instance-initiated-shutdown-behavior terminate \
    --block-device-mappings DeviceName=/dev/sda1,Ebs={DeleteOnTermination=true} \
    --user-data file://Tests/scripts/shutdown_instance.sh \
    --query 'Instances[0].InstanceId' | tr -d '"')

if [ -z ${INSTANCE_ID} ]
then
    echo "Instance failed to start"
    exit 1
fi

echo "Instance ID is: $INSTANCE_ID"
echo ${INSTANCE_ID} > instance_ids

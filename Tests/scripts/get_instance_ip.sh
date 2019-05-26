#!/usr/bin/env bash
set -e

INSTANCE_ID=$1

echo "Making sure instance started"
aws ec2 wait instance-exists --instance-ids ${INSTANCE_ID}
aws ec2 wait instance-running --instance-ids ${INSTANCE_ID}
echo "Instance started. fetching IP"

PUBLIC_IP=$(aws ec2 describe-instances --instance-ids ${INSTANCE_ID} \
    --query 'Reservations[0].Instances[0].PublicIpAddress' | tr -d '"')
echo "Instance public IP is: $PUBLIC_IP"

echo ${PUBLIC_IP} > public_ip
echo ${PUBLIC_IP} > ./Tests/instance_ips.txt
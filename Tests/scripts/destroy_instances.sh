#!/usr/bin/env bash
set -e

INSTANCE_ID=$(cat instance_ids)
USER=centos

#destroy instance
echo "Terminating instance: ${INSTANCE_ID}"
aws ec2 terminate-instances --instance-id ${INSTANCE_ID}
echo "Waiting for instance: ${INSTANCE_ID} to terminate"
aws ec2 wait instance-terminated --instance-ids ${INSTANCE_ID}
echo "Done!"


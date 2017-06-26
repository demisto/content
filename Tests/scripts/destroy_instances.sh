#!/usr/bin/env bash
set -e

INSTANCE_ID=$(cat instance_ids)
PUBLIC_IP=$(cat public_ip)
USER=centos

echo "Copying logs from: ${USER}@${PUBLIC_IP}:/var/log/demisto/server.log"

#first get logs
scp ${USER}@${PUBLIC_IP}:/var/log/demisto/server.log $CIRCLE_ARTIFACTS

#destroy instance
echo "Terminating instance: ${INSTANCE_ID}"
aws ec2 terminate-instances --instance-id ${INSTANCE_ID}
echo "Waiting for instance: ${INSTANCE_ID} to terminate"
aws ec2 wait instance-terminated --instance-ids ${INSTANCE_ID}
echo "Done!"


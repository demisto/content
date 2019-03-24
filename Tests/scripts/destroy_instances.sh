#!/usr/bin/env bash
set -e

echo "checking for $4"
if [ -f "$4" ]; then
    echo "Run Tests has failed, not Destroying instance"
    rm -rf "$4"
else
   if [ -z "$2" ]
     then
       INSTANCE_ID=$1
    else
       INSTANCE_ID=$(cat instance_ids)
   fi

   if [ -z "$3" ]
     then
       PUBLIC_IP=$3
     else
       PUBLIC_IP=$(cat public_ip)
   fi
   USER="ec2-user"

   # collect log file to artifacts

   ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${USER}@${PUBLIC_IP} "sudo chmod -R 755 /var/log/demisto"
   scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${USER}@${PUBLIC_IP}:/var/log/demisto/server.log $1 || echo "WARN: Failed downloading server.log"

   #destroy instance
   echo "Terminating instance: ${INSTANCE_ID}"
   aws ec2 terminate-instances --instance-id ${INSTANCE_ID}
   echo "Waiting for instance: ${INSTANCE_ID} to terminate"
   aws ec2 wait instance-terminated --instance-ids ${INSTANCE_ID}
   echo "Done!"
fi



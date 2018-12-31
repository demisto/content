#!/usr/bin/env bash
if [ -f ./Tests/is_build_failed.txt ]; then
    echo "Run Tests has failed, not Destroying instance"
    rm -rf ./Tests/is_build_failed.txt
else
   set -e

   INSTANCE_ID=$(cat instance_ids)
   USER="ec2-user"

   # collect log file to artifacts
   PUBLIC_IP=$(cat public_ip)
   ssh -t ${USER}@${PUBLIC_IP} "sudo chmod -R 755 /var/log/demisto/server.log"
   scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${USER}@${PUBLIC_IP}:/var/log/demisto/server.log $1

   #destroy instance
   echo "Terminating instance: ${INSTANCE_ID}"
   aws ec2 terminate-instances --instance-id ${INSTANCE_ID}
   echo "Waiting for instance: ${INSTANCE_ID} to terminate"
   aws ec2 wait instance-terminated --instance-ids ${INSTANCE_ID}
   echo "Done!"
fi



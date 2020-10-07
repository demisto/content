#!/usr/bin/env bash
set -e

INSTANCE_ID=$(cat ./env_results.json | jq .[0].InstanceID | sed "s/\"//g")

PUBLIC_IP=$(cat ./env_results.json | jq .[0].InstanceDNS | sed "s/\"//g")
echo "Instance public IP is: $PUBLIC_IP"

echo ${PUBLIC_IP} > public_ip

USER="ec2-user"

echo "wait 90 seconds to ensure server is ready for ssh"
sleep 90s

echo "add instance to known hosts"
ssh-keyscan -H ${PUBLIC_IP} >> ~/.ssh/known_hosts

USER="ec2-user"

# copy content files
ssh ${USER}@${PUBLIC_IP} 'mkdir ~/content'
ssh ${USER}@${PUBLIC_IP} 'mkdir ~/TestPlaybooks'
#ssh ${USER}@${PUBLIC_IP} 'mkdir ~/Beta_Integrations'

scp artifacts/content_new.zip ${USER}@${PUBLIC_IP}:~/content
scp artifacts/content_test.zip ${USER}@${PUBLIC_IP}:~/content
#scp -r ./Beta_Integrations/* ${USER}@${PUBLIC_IP}:~/Beta_Integrations

# override exiting content with current
COPY_CONTENT_COMMAND="sudo unzip -o ~/content/content_new.zip -d /usr/local/demisto/res \
    && sudo unzip -o ~/content/content_test.zip -d /usr/local/demisto/res"
ssh -t ${USER}@${PUBLIC_IP} ${COPY_CONTENT_COMMAND}

echo "start server"

START_SERVER_COMMAND="sudo systemctl start demisto"
ssh -t ${USER}@${PUBLIC_IP} ${START_SERVER_COMMAND}

echo "wait for server to start on ip $PUBLIC_IP"

wget --retry-connrefused --no-check-certificate -T 60 "https://${PUBLIC_IP}:443"

# pull needed docker image, this is a workaround until https://github.com/demisto/server/issues/7827 is solved
ssh -t ${USER}@${PUBLIC_IP} "sudo docker pull demisto/threatconnect-sdk"

echo "server started!"

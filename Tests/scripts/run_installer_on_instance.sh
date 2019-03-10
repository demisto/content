#!/usr/bin/env bash
set -e

INSTANCE_ID=$(cat instance_ids)

echo "Making sure instance started"
aws ec2 wait instance-exists --instance-ids ${INSTANCE_ID}
aws ec2 wait instance-running --instance-ids ${INSTANCE_ID}
echo "Instance started. fetching IP"

PUBLIC_IP=$(aws ec2 describe-instances --instance-ids ${INSTANCE_ID} \
    --query 'Reservations[0].Instances[0].PublicIpAddress' | tr -d '"')
echo "Instance public IP is: $PUBLIC_IP"

echo ${PUBLIC_IP} > public_ip

USER="ec2-user"

echo "wait 90 seconds to ensure server is ready for ssh"
sleep 90s

echo "add instance to known hosts"
ssh-keyscan -H ${PUBLIC_IP} >> ~/.ssh/known_hosts

# install mitmproxy
ssh ${USER}@${PUBLIC_IP} 'wget https://snapshots.mitmproxy.org/4.0.4/mitmproxy-4.0.4-linux.tar.gz'
ssh ${USER}@${PUBLIC_IP} 'tar -xzvf mitmproxy-4.0.4-linux.tar.gz'
ssh ${USER}@${PUBLIC_IP} 'rm mitmproxy-4.0.4-linux.tar.gz'
ssh ${USER}@${PUBLIC_IP} 'sudo chmod +x mitm*'
ssh ${USER}@${PUBLIC_IP} 'sudo mv mitm* /usr/local/bin'

ssh ${USER}@${PUBLIC_IP} 'mkdir ~/content'
ssh ${USER}@${PUBLIC_IP} 'mkdir ~/TestPlaybooks'
ssh ${USER}@${PUBLIC_IP} 'mkdir ~/Beta_Integrations'

scp content_new.zip ${USER}@${PUBLIC_IP}:~/content
scp content_test.zip ${USER}@${PUBLIC_IP}:~/content
scp -r ./Beta_Integrations/* ${USER}@${PUBLIC_IP}:~/Beta_Integrations

# override exiting content with current
COPY_CONTENT_COMMAND="sudo unzip -o ~/content/content_new.zip -d /usr/local/demisto/res \
    && sudo unzip -o ~/content/content_test.zip -d /usr/local/demisto/res && sudo cp -r ~/Beta_Integrations/* /usr/local/demisto/res"
ssh -t ${USER}@${PUBLIC_IP} ${COPY_CONTENT_COMMAND}

echo "start server"

START_SERVER_COMMAND="sudo systemctl start demisto"
ssh -t ${USER}@${PUBLIC_IP} ${START_SERVER_COMMAND}

echo "wait for server to start on ip $PUBLIC_IP"

wget --retry-connrefused --no-check-certificate -T 60 "https://${PUBLIC_IP}:443"

# pull needed docker image, this is a workaround until https://github.com/demisto/server/issues/7827 is solved
ssh -t ${USER}@${PUBLIC_IP} "sudo docker pull demisto/threatconnect-sdk"

echo "server started!"

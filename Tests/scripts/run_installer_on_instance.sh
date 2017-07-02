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

#copy installer files to instance
INSTALLER=$(ls demistoserver*.sh)

USER="centos"

EXP_FILE="./Tests/scripts/installer_commands.exp"

echo "wait 1 minute to ensure server is ready for ssh"
sleep 1m

echo "create installer files folder"
ssh ${USER}@${PUBLIC_IP} 'mkdir -p ~/installer_files'

scp ${EXP_FILE} ${USER}@${PUBLIC_IP}:~/installer_files/installer_commands.exp
scp ${INSTALLER} ${USER}@${PUBLIC_IP}:~/installer_files/installer.sh

echo "get installer and run installation script"
INSTALL_COMMAND="cd ~/installer_files \
    && sudo yum install -y -q expect less \
    && chmod +x installer.sh \
    && sudo expect installer_commands.exp"
ssh -t ${USER}@${PUBLIC_IP} ${INSTALL_COMMAND}

echo "server is ready to start!"

echo "update server with branch content"

ssh ${USER}@${PUBLIC_IP} 'mkdir -p ~/content'
ls
scp -r content.zip ${USER}@${PUBLIC_IP}:~/content

echo "unzip..."

# override exiting content with current
COPY_CONTENT_COMMAND="sudo unzip ~/content/content.zip -d /usr/local/demisto/res"
ssh -t ${USER}@${PUBLIC_IP} ${COPY_CONTENT_COMMAND}

echo "start server"

START_SERVER_COMMAND="sudo systemctl start demisto"
ssh -t ${USER}@${PUBLIC_IP} ${START_SERVER_COMMAND}

echo "wait for server to start on ip $PUBLIC_IP"

wget --retry-connrefused --no-check-certificate -T 60 "https://${PUBLIC_IP}:443"

echo "server started!"
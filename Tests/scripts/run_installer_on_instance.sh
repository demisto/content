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
INSTALL_COMMAND="yum"

EXP_FILE="./Tests/scripts/installer_commands-centos.exp"

echo "create installer files folder"
ssh ${USER}@${PUBLIC_IP} 'mkdir -p ~/installer_files'

echo "copy exp file"
scp ${EXP_FILE} ${USER}@${PUBLIC_IP}:~/installer_files/installer_commands.exp

echo "copy installer file"
scp ${INSTALLER} ${USER}@${PUBLIC_IP}:~/installer_files/installer.sh

echo "get installer and run installation script"
SSH_COMMAND="cd ~/installer_files \
    && sudo ${INSTALL_COMMAND} install -y -q expect less \
    && chmod +x installer.sh \
    && sudo expect installer_commands.exp"
ssh -t ${USER}@${PUBLIC_IP} ${SSH_COMMAND}

echo "wait for server to start"
wget --retry-connrefused --no-check-certificate -T 60 "https://${PUBLIC_IP}:443"

echo "server started!"
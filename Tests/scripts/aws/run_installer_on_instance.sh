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

exit 0

#copy installer files to instance
INSTALLER=$(ls $CIRCLE_ARTIFACTS/demistoserver*.sh)

USER="centos"
INSTALL_COMMAND="yum"
EXP_FILE="./scripts/aws/installer_commands-centos.exp"

: '
case $CIRCLE_NODE_INDEX in
    0)
        echo 'Testing against RHEL remote server'
        USER="ec2-user"
        ;;
    1)
        echo 'Testing against ubuntu remote server'
        USER="ubuntu"
        INSTALL_COMMAND="apt-get"
        EXP_FILE="./scripts/aws/installer_commands-ubuntu.exp"
        ;;
    2)
        echo 'Testing against centos multi tenant remote server'
        cp ./scripts/aws/installer_commands-centos.exp ./scripts/aws/installer_commands-mt.exp
        sed -i -- "s|bash installer.sh|bash installer.sh -- -multi-tenant|g" ./scripts/aws/installer_commands-mt.exp
        EXP_FILE="./scripts/aws/installer_commands-mt.exp"
        ;;
    esac
'

echo "create installer files folder"
ssh ${USER}@${PUBLIC_IP} 'mkdir -p ~/installer_files'

echo "copy installer files"
scp ${EXP_FILE} ${USER}@${PUBLIC_IP}:~/installer_files/installer_commands.exp
scp ${INSTALLER} ${USER}@${PUBLIC_IP}:~/installer_files/installer.sh
scp ./conf_for_systemtests-e2e ${USER}@${PUBLIC_IP}:~/installer_files/conf_for_systemtests

echo "get installer and run installation script"
SSH_COMMAND="cd ~/installer_files \
    && sudo cp conf_for_systemtests /etc/demisto.conf
    && sudo ${INSTALL_COMMAND} install -y -q expect less \
    && chmod +x installer.sh \
    && sudo expect installer_commands.exp"
ssh -t ${USER}@${PUBLIC_IP} ${SSH_COMMAND}

# wait for server to start
wget --retry-connrefused --no-check-certificate -T 60 "https://${PUBLIC_IP}:443"


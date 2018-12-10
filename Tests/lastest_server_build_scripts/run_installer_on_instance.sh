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

echo "wait 90 seconds to ensure server is ready for ssh"
sleep 90s

echo "add instance to known hosts"
ssh-keyscan -H ${PUBLIC_IP} >> ~/.ssh/known_hosts

echo "create installer files folder"
ssh ${USER}@${PUBLIC_IP} 'mkdir -p ~/installer_files'

scp ${INSTALLER} ${USER}@${PUBLIC_IP}:~/installer_files/installer.sh

# copy licence to instance
DEMISTO_LIC_PATH=$(cat demisto_lic_path)
scp ${DEMISTO_LIC_PATH} ${USER}@${PUBLIC_IP}:~/installer_files/demisto.lic

DEMISTO_SEVERCONF_PATH=$(cat demisto_conf_path)
scp ${DEMISTO_SEVERCONF_PATH} ${USER}@${PUBLIC_IP}:~/installer_files/demisto.conf

echo "get installer and run installation script"
INSTALL_COMMAND_Y="cd ~/installer_files \
    && chmod +x installer.sh \
    && sudo mkdir /usr/local/demisto \
    && sudo cp demisto.lic /usr/local/demisto/ \
    && sudo ./installer.sh -- -y -do-not-start-server \
    && sudo cp demisto.conf /etc/demisto.conf"

ssh -t ${USER}@${PUBLIC_IP} ${INSTALL_COMMAND_Y}

echo "server is ready to start!"

echo "update server with branch content"

ssh ${USER}@${PUBLIC_IP} 'mkdir ~/content'
ssh ${USER}@${PUBLIC_IP} 'mkdir ~/TestPlaybooks'
ssh ${USER}@${PUBLIC_IP} 'mkdir ~/Beta_Integrations'

scp content_new.zip ${USER}@${PUBLIC_IP}:~/content
scp content_test.zip ${USER}@${PUBLIC_IP}:~/content
scp -r ./Beta_Integrations/* ${USER}@${PUBLIC_IP}:~/Beta_Integrations

# override exiting content with current
COPY_CONTENT_COMMAND="sudo unzip -o ~/content/content_new.zip -d /usr/local/demisto/res \
    && sudo unzip -o ~/content/content_test.zip -d /usr/local/demisto/res && sudo cp ~/Beta_Integrations/* /usr/local/demisto/res"
ssh -t ${USER}@${PUBLIC_IP} ${COPY_CONTENT_COMMAND}

echo "start server"

START_SERVER_COMMAND="sudo systemctl start demisto"
ssh -t ${USER}@${PUBLIC_IP} ${START_SERVER_COMMAND}

echo "wait for server to start on ip $PUBLIC_IP"

wget --retry-connrefused --no-check-certificate -T 60 "https://${PUBLIC_IP}:443"

# pull needed docker image, this is a workaround until https://github.com/demisto/server/issues/7827 is solved
ssh -t ${USER}@${PUBLIC_IP} "sudo docker pull demisto/threatconnect-sdk"

echo "server started!"

#!/usr/bin/env bash
set -e

PUBLIC_IP=$1

USER="ec2-user"


echo "[`date`] ${PUBLIC_IP}: add instance to known hosts"
ssh-keyscan -H ${PUBLIC_IP} >> ~/.ssh/known_hosts

MOCKS_SETUP_DEPS_COMMAND=`cat ./Tests/scripts/ami_mock_dependencies_setup.sh`
ssh ${USER}@${PUBLIC_IP} "eval ${MOCKS_SETUP_DEPS_COMMAND}" &>/dev/null

echo "increasing MaxStartups in sshd_config to prevent the 'ssh_exchange_identification: Connection closed by remote host' error"
MODIFY_SSHD_CONFIG_CMD='sudo sed -i "s/#MaxStartups 10:30:100/MaxStartups 20:30:100/g" /etc/ssh/sshd_config'
ssh -t ${USER}@${PUBLIC_IP} ${MODIFY_SSHD_CONFIG_CMD}

echo "restarting sshd"
RESTART_SSHD_CMD="sudo service sshd restart"
ssh -t ${USER}@${PUBLIC_IP} ${RESTART_SSHD_CMD}

echo "[`date`] ${PUBLIC_IP}: start server"

START_SERVER_COMMAND="sudo systemctl start demisto"
ssh -t ${USER}@${PUBLIC_IP} ${START_SERVER_COMMAND}

echo "[`date`] ${PUBLIC_IP}: wait for server to start on ip"

wget --retry-connrefused --no-check-certificate -T 60 "https://${PUBLIC_IP}:443"

echo "[`date`] ${PUBLIC_IP}: server started!"

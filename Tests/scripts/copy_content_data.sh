#!/usr/bin/env bash
set -e

PUBLIC_IP=$1

USER="ec2-user"


echo "[`date`] ${PUBLIC_IP}: add instance to known hosts"
ssh-keyscan -H ${PUBLIC_IP} >> ~/.ssh/known_hosts

# copy content files
ssh ${USER}@${PUBLIC_IP} 'mkdir ~/content'
ssh ${USER}@${PUBLIC_IP} 'mkdir ~/TestPlaybooks'
ssh ${USER}@${PUBLIC_IP} 'mkdir ~/Beta_Integrations'

scp $(find ./Beta_Integrations/ -maxdepth 1 -type f) ${USER}@${PUBLIC_IP}:~/Beta_Integrations

# override exiting content with current
# rm CommonServer*_4_1 as this was changed and is stuck on 4.1 server
COPY_CONTENT_COMMAND="sudo rm -f /usr/local/demisto/res/playbook-Test Playbook TrendMicroDDA.yml \
  sudo rm -f /usr/local/demisto/res/script-CommonServer_4_1.yml \
  /usr/local/demisto/res/script-CommonServerPython_4_1.yml \
  /usr/local/demisto/res/integration-Windows_Defender_Advanced_Threat_Protection.yml /usr/local/demisto/res/integration-Microsoft_Graph.yml \
  /usr/local/demisto/res/integration-Awake_Security.yml /usr/local/demisto/res/integration-WhatsMyBrowser.yml \
  && sudo cp -r ~/Beta_Integrations/* /usr/local/demisto/res"

if [[ "$CIRCLE_BRANCH" != "master" ]] || [[ -n "$NIGHTLY" ]]; then
  # when triggered on non master branch sideload like we used to do
  scp artifacts/content_new.zip ${USER}@${PUBLIC_IP}:~/content
  scp artifacts/content_test.zip ${USER}@${PUBLIC_IP}:~/content
  COPY_CONTENT_COMMAND="$COPY_CONTENT_COMMAND && sudo unzip -q -o ~/content/content_new.zip -d /usr/local/demisto/res \
  && sudo unzip -q -o ~/content/content_test.zip -d /usr/local/demisto/res"
fi

ssh -t ${USER}@${PUBLIC_IP} ${COPY_CONTENT_COMMAND}

echo "[`date`] ${PUBLIC_IP}: start server"

START_SERVER_COMMAND="sudo systemctl start demisto"
ssh -t ${USER}@${PUBLIC_IP} ${START_SERVER_COMMAND}

echo "[`date`] ${PUBLIC_IP}: wait for server to start on ip"

wget --retry-connrefused --no-check-certificate -T 60 "https://${PUBLIC_IP}:443"

echo "[`date`] ${PUBLIC_IP}: server started!"

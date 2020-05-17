#!/usr/bin/bash
echo "Starting mitmproxy dependencies setup"
echo "-------------------------------------"

sudo yum -y install python3
python3 -m pip install --user pipx
# disable-secrets-detection-start
echo "
export PATH=$HOME/.local/bin:$PATH" >> ~/.bash_profile
# disable-secrets-detection-end
source ~/.bash_profile
pipx install mitmproxy
pipx inject mitmproxy python-dateutil

echo "'mitmproxy' installed and 'python-dateutil' dependency injected"
echo "mitmproxy dependencies setup completed"
echo "--------------------------------------"

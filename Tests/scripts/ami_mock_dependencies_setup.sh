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

echo "increasing MaxStartups in sshd_config to prevent the 'ssh_exchange_identification: Connection closed by remote host' error"
sudo sed -i "s/#MaxStartups 10:30:100/MaxStartups 20:30:100/g" /etc/ssh/sshd_config
echo "restarting sshd"
sudo kill -SIGHUP $(pgrep -f "sshd -D")

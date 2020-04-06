#!/usr/bin/bash
echo "Starting mitmproxy dependencies setup"
echo "-------------------------------------"
echo "Installing development requirements for installing python3 on Linux Amazon 2 instance."
sudo yum -y install gcc bzip2-devel ncurses-devel gdbm-devel xz-devel sqlite-devel 
sudo yum -y install openssl-devel tk-devel uuid-devel readline-devel zlib-devel libffi-devel
echo "Downloading python3 source binaries."
# disable-secrets-detection-start
wget https://www.python.org/ftp/python/3.8.0/Python-3.8.0.tgz
# disable-secrets-detection-end
tar xzf Python-3.8.0.tgz
cd Python-3.8.0
./configure
sudo make -j 8
sudo make altinstall
echo "Python3.8 installed."
sudo ln -s /usr/local/bin/python3.8 /usr/bin/python3
python3 -m pip install -U pip --user
sudo ln -s ~/.local/bin/pip /usr/local/bin/pip
pip install python-dateutil --user
pip install mitmproxy --user
# disable-secrets-detection-start
echo "
export PATH=$HOME/.local/bin:$PATH" >> ~/.bash_profile
# disable-secrets-detection-end
source ~/.bash_profile
echo "Python 'python-dateutil' and 'mitmproxy' installed."
echo "mitmproxy dependencies setup completed"
echo "--------------------------------------"

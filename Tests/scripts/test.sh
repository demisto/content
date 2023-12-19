#!/bin/bash
echo "-----------------------------------------"
echo "running: pwd and ls -la"
pwd
ls -la
echo "-----------------------------------------"
echo "running: sudo apt-get install whois"
sudo apt-get install whois
echo "running: whois google.co.uk (wihtout proxy)"
whois google.co.uk

echo "running: chmod +x ./Packs/Whois/Integrations/Whois/test_data/microsocks"
chmod +x ./Packs/Whois/Integrations/Whois/test_data/microsocks # grant permissions to execute
./Packs/Whois/Integrations/Whois/test_data/microsocks -p 9980 &
pid=$!
echo "running: microsocks on pid: $pid"

sleep 5
echo "running: netstat -p tcp -l -n | grep 9980"
apt-get install net-tools -y
netstat -p tcp -l -n | grep 9980

echo "running: whois google.co.uk (with proxy)"
whois google.co.uk

#echo "running command: ss -tln | grep 9980"
#ss -tln | grep 9980
# apt-get install lsof -y
#echo "running command: lsof -i :9980"
# lsof -i :9980


kill $pid
echo "killed darwin on pid: $pid"
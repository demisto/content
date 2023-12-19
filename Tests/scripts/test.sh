#!/bin/bash
echo "-----------------------------------------"
echo "running: pwd and ls -la"
pwd
ls -la
echo "-----------------------------------------"
echo "running: apt-get install dnsutils"
apt-get install dnsutils
echo "-----------------------------------------"
echo "running: apt-get install whois"
apt-get install whois
echo "running: whois google.co.uk (wihtout proxy)"
whois -v google.co.uk
echo "-----------------------------------------"
echo "running: dig +short google.co.uk whois"
dig +short google.co.uk whois
echo "-----------------------------------------"
echo "running: chmod +x ./Packs/Whois/Integrations/Whois/test_data/microsocks"
chmod +x ./Packs/Whois/Integrations/Whois/test_data/microsocks # grant permissions to execute
./Packs/Whois/Integrations/Whois/test_data/microsocks -p 9980 &
pid=$!
echo "successfuly running microsocks on pid: $pid"
echo "-----------------------------------------"
sleep 5
echo "running: netstat -p tcp -l -n | grep 9980"
apt-get install net-tools -y
netstat -p tcp -l -n | grep 9980
echo "-----------------------------------------"
echo "running: whois google.co.uk (with proxy)"
whois google.co.uk
echo "-----------------------------------------"
echo "running: dig +short google.co.uk whois"
dig +short google.co.uk whois
echo "-----------------------------------------"
#echo "running command: ss -tln | grep 9980"
#ss -tln | grep 9980
# apt-get install lsof -y
#echo "running command: lsof -i :9980"
# lsof -i :9980
echo "-----------------------------------------"
kill $pid
echo "killed darwin on pid: $pid"
echo "-----------------------------------------"
#!/bin/bash
echo "-----------------------------------------"
pwd
ls -la
echo "-----------------------------------------"
chmod +x darwin # grant permissions to execute
./Packs/Whois/Integrations/Whois/test_data/microsocks_darwin -p 9980 &pid=$!
echo "running darwin on pid: $pid"
sleep 5
echo "running command: netstat -p tcp -l -n | grep 9980"
netstat -p tcp -l -n | grep 9980
echo "running command: ss -tln | grep 9980"
ss -tln | grep 9980
echo "running command: lsof -i :9980"
lsof -i :9980
kill $pid
echo "killed darwin on pid: $pid"
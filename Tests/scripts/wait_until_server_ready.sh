#!/usr/bin/env bash
set -e

SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"

CHECKURL="https://$SERVER_IP:443/health/server"
count=0
stcode=$(curl -i --write-out "%{http_code}" --silent --insecure --output /dev/null "$CHECKURL")
while [ $stcode -ne "200" ]
do
    echo "Sending to $CHECKURL, response code: $stcode"
    printf 'Waiting for server to start...\n'
    sleep 2
    if [ $count -eq 1200 ]
    then
        printf 'Gave up, server is down...\n'
        exit 1
    fi;
    stcode=$(curl -i --write-out "%{http_code}" --silent --insecure --output /dev/null "$CHECKURL")
    ((count++))
done
exit 0
#!/usr/bin/env bash
set -e

SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"
GET_HTTP_CODE_COMMAND="curl --write-out %{http_code} --silent --output /dev/null $SERVER_URL/user -k"

NEXT_WAIT_TIME=0
HTTP_CODE=$($GET_HTTP_CODE_COMMAND)

MAX_TRIES=5
TRY_COUNT=1
until [ $HTTP_CODE != 433 ] || [ $TRY_COUNT = $MAX_TRIES ]; do
    echo "server is not ready - wait another 1 minute"
   sleep 1m
   ((TRY_COUNT++))
   HTTP_CODE=$($GET_HTTP_CODE_COMMAND)
done

if [ $HTTP_CODE = 433 ]
then
    echo "Server is not ready :("
    exit 1
fi

echo "Server is ready :)"


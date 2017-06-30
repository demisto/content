SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"
GET_HTTP_CODE_COMMAND="curl --write-out %{http_code} --silent --output /dev/null $SERVER_URL -k"

NEXT_WAIT_TIME=0
HTTP_CODE=$($GET_HTTP_CODE_COMMAND)
echo "HTTP_CODE = $HTTP_CODE"

MAX_TRIES=5
until ["$HTTP_CODE" -eq "200"] || [ $NEXT_WAIT_TIME -eq $MAX_TRIES ]; do
   sleep 1m
   ((MAX_TRIES++))
   HTTP_CODE=$($GET_HTTP_CODE_COMMAND)
    echo "HTTP_CODE = $HTTP_CODE"
done

echo "FINAL HTTP_CODE= $HTTP_CODE"

sleep 2m


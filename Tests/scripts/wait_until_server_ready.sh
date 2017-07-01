SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"
GET_HTTP_CODE_COMMAND="curl --write-out %{http_code} --silent --output /dev/null $SERVER_URL/user -k"

NEXT_WAIT_TIME=0
HTTP_CODE=$($GET_HTTP_CODE_COMMAND)
echo "HTTP_CODE = $HTTP_CODE"
echo "GET_HTTP_CODE_COMMAND_SECURE = $GET_HTTP_CODE_COMMAND_SECURE"

MAX_TRIES=5
until [ $HTTP_CODE = 433 ] || [ $NEXT_WAIT_TIME = $MAX_TRIES ]; do
   sleep 30s
   ((MAX_TRIES++))
   HTTP_CODE=$($GET_HTTP_CODE_COMMAND)
    echo "HTTP_CODE = $HTTP_CODE"
done

echo "FINAL HTTP_CODE= $HTTP_CODE"

sleep 2m


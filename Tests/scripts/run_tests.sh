echo "start content tests"

SECRET_CONF_PATH=$(cat secret_conf_path)
USERNAME="admin"
PASSWORD=$(cat $SECRET_CONF_PATH | jq '.adminPassword')
SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"
CONF_PATH="./Tests/conf.json"

echo "SECRET_CONF_PATH - $SECRET_CONF_PATH"
echo "PASSWORD - $PASSWORD"
cat $SECRET_CONF_PATH

echo "Starts tests with server url - $SERVER_URL\n"
python ./Tests/test_content.py -u "$USERNAME" -p "$PASSWORD" -s "$SERVER_URL" -c "$CONF_PATH" -e "$SECRET_CONF_PATH"
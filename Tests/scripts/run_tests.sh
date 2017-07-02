echo "start content tests"

USERNAME="admin"
PASSWORD=$(cat admin_password)
SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"
CONF_PATH="./conf.json"
SECRET_CONF_PATH=$(cat secret_conf_path)

echo "Starts tests with server url - $SERVER_URL"
python ./Tests/test_content.py -u "$USERNAME" -p "$PASSWORD" -s "$SERVER_URL" -c "$CONF_PATH" -e "$SECRET_CONF_PATH"
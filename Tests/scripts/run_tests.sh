echo "start content tests"

USERNAME="admin"
PASSWORD=$(cat admin_password)
SERVER_IP=$(cat public_ip)
SERVER_URL="https://$SERVER_IP"
CONF_PATH=$(cat conf_path)
echo "paramters: USERNAME=$USERNAME, PASSWORD=$PASSWORD, SERVER_URL=$SERVER_URL, USERNAME=$CONF_PATH"
python ./Tests/test_content.py -u "$USERNAME" -p "$PASSWORD"ssh -s "$SERVER_URL" -c "$CONF_PATH"
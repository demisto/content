#!/usr/bin/env bash
set -e

SECRET_CONF_PATH=$(cat secret_conf_path)

ADMIN_PASSWORD=$(cat $SECRET_CONF_PATH | jq '.adminPassword')

# remove quotes from password
temp="${ADMIN_PASSWORD%\"}"
temp="${temp#\"}"
ADMIN_PASSWORD=$temp

echo ${ADMIN_PASSWORD} > admin_password

# create exp of password
ADMIN_EXP=$(echo $ADMIN_PASSWORD | sed -e 's/\(.\)/send -- "\1"\nexpect -exact "*"\n/g' | sed ':a $!{N; ba}; s/\n/\\n/g')

sed -i "s/<PASSWORD>/$ADMIN_EXP/g" ./Tests/scripts/installer_commands.exp

echo "Done!"
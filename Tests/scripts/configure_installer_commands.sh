#!/usr/bin/env bash
set -e

ADMIN_CREDENTIALS=$(cat ./conf.json | jq '.admin')

# remove quotes from cred
temp="${ADMIN_CREDENTIALS%\"}"
temp="${temp#\"}"
ADMIN_CREDENTIALS=$temp

# create exp of password
ADMIN_EXP=$(echo $ADMIN_CREDENTIALS | sed -e 's/\(.\)/send -- "\1"\nexpect -exact "*"\n/g' | sed ':a $!{N; ba}; s/\n/\\n/g')

sed -i "s/<PASSWORD>/$ADMIN_EXP/g" ./Tests/scripts/installer_commands.exp

echo "Done!"
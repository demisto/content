#!/usr/bin/env bash
set -e

ADMIN_CREDENTIALS=$(cat ./conf.json | jq '.admin')

# remove quotes
temp="${ADMIN_CREDENTIALS%\"}"
temp="${temp#\"}"
ADMIN_CREDENTIALS=$temp

echo "ADMIN_CREDENTIALS = ${ADMIN_CREDENTIALS}"

ADMIN_EXP=$(echo $ADMIN_CREDENTIALS | sed -e 's/\(.\)/send -- "\1"\nexpect -exact "*"\n/g')
echo "ADMIN_EXP = ${ADMIN_EXP}"

#cat ./Tests/scripts/installer_commands-centos.exp
sed -i "s/<PASSWORD>/$ADMIN_EXP/g" ./Tests/scripts/installer_commands-centos.exp

cat ./Tests/scripts/installer_commands-centos.exp
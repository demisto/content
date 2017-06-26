#!/usr/bin/env bash
set -e

echo "start"
ADMIN_CREDENTIALS=$(cat ./conf.json | jq '.admin')
echo "ADMIN_CREDENTIALS = ${ADMIN_CREDENTIALS}"

ADMIN_EXP=$(echo $ADMIN_CREDENTIALS | sed -e 's/\(.\)/send -- "\1"\nexpect -exact "*"\n/g')
echo "ADMIN_EXP = ${ADMIN_EXP}"

echo "BEFORE"
cat ./Tests/scripts/installer_commands-centos.exp
sed -i "s/<PASSWORD>/$ADMIN_EXP/g" ./Tests/scripts/installer_commands-centos.exp

echo "AFTER"
cat ./Tests/scripts/installer_commands-centos.exp
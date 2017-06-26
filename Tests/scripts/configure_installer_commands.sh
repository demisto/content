#!/usr/bin/env bash
set -e

ADMIN_CREDENTIALS=$(cat ./conf.json | jq '.admin')
echo "ADMIN_CREDENTIALS = ${ADMIN_CREDENTIALS}"

cat ./Tests/scripts/installer_commands-centos.exp
sed -i "s/<PASSWORD>/$ADMIN_EXP/g" ./Tests/scripts/installer_commands-centos.exp
#!/usr/bin/env bash
set -e

echo "start"
#ADMIN_CREDENTIALS=$(cat ./conf.json | jq '.admin')
echo "ADMIN_CREDENTIALS = ${ADMIN_CREDENTIALS}"

ADMIN_EXP=$(echo $ADMIN_CREDENTIALS | sed -e 's/\(.\)/send -- "\1"\nexpect -exact "*"\n/g')
echo "ADMIN_EXP = ${ADMIN_EXP}"

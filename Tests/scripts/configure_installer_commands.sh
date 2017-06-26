#!/usr/bin/env bash
set -e
ADMIN_CREDENTIALS=$(cat ./conf.json | jq '.admin')
echo "ADMIN_CREDENTIALS = ${ADMIN_CREDENTIALS}"

for (( i=0; i<${#ADMIN_CREDENTIALS}; i++ )); do
  echo "${ADMIN_CREDENTIALS:$i:1}"
done



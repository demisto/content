#!/usr/bin/env bash
set -e

echo "configure installer commands start"

cat ./conf.json

goldi=$(cat ./conf.json | jq '.goldi')
echo "goldy = ${goldi}"

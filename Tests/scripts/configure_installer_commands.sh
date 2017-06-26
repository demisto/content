#!/usr/bin/env bash
set -e


echo "configure installer commands start"
read -r -d '' someVar << EOM
send -- "a"
expect -exact "*"
send -- "d"
expect -exact "*"
send -- "m"
expect -exact "*"
send -- "i"
expect -exact "*"
send -- "n"
EOM

echo "someVar = ${someVar}"

cat ./conf.json
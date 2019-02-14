#!/usr/bin/env bash
set -e
cat >~/.gitconfig << EOF
[user]
       name = EC2 Default User
       email = ec2-user@$HOSTNAME
EOF
cd content-test-data
git add *
git commit -m "Updated mock files from content branch $1 build $2"
git push

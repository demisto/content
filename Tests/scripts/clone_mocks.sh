#!/usr/bin/env bash

cat >> ~/.ssh/config << EOF
host github.com
 HostName github.com
 IdentityFile $1
 User git
EOF

chmod 600 ~/.ssh/config

git clone git@github.com:demisto/content-test-data.git

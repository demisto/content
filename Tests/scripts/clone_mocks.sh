#!/usr/bin/env bash
set -e

cat > ~/.ssh/config << EOF
host github.com
 HostName github.com
 IdentityFile $1
 User git
EOF

chmod 600 ~/.ssh/config

ssh-keyscan github.com >> ~/.ssh/known_hosts

if [[ ! -d "content-test-data" ]]; then
    git clone git@github.com:demisto/content-test-data.git
fi
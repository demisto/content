#!/bin/sh

# Setup a container for dev testing. 
#
# In alpine will install necessary python dev tools and then use pip to install

cp /dev/stdin /pkg-dev-test-requirements.txt

pip install -r /pkg-dev-test-requirements.txt

# for alpine we install dev dependencies to support dependencies that need native code (seen with typed_ast)
if [ -f "/etc/alpine-release" ]; then
    apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget
fi

pip install -r /pkg-dev-test-requirements.txt

# remove the dev dependencies
if [ -f "/etc/alpine-release" ]; then
    apk del .build-dependencies
fi


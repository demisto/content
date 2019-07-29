#!/bin/sh

# Setup a container for dev testing. 
#
# In alpine will install necessary python dev tools and then use pip to install

# exit on errors
set -e

# /dev/stdin is coming in in the format of a requirements file as pip install expects to receive
# see code at pgk_dev_tasks_in_docker.py (method: docker_image_create)
cp /dev/stdin /pkg-dev-test-requirements.txt

# for alpine we install dev dependencies to support dependencies that need native code (seen with typed_ast)
if [ -f "/etc/alpine-release" ]; then
    apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget
fi

pip install -r /pkg-dev-test-requirements.txt

# remove the dev dependencies
if [ -f "/etc/alpine-release" ]; then
    apk del .build-dependencies
fi

mkdir /devwork
chown :4000 /devwork
chmod 775 /devwork

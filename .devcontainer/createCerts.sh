#!/bin/bash

# This script should run in the devcontainer.
# This script creates a local certificate file.
# It tries to connect to a server (for instance, github), show the local certificates and save it to a file.

# We connect to a random server and not paloaltonetworks.com to get external certificates. 
CONNECT_SERVER="github.com:443"

FILE=$1

REGEX_BEGIN="/^-----BEGIN CERTIFICATE-----$/"
REGEX_END="/^-----END CERTIFICATE-----$"

# Parse the certificate to a file
openssl s_client -showcerts -connect $CONNECT_SERVER | \
    sed -n "$REGEX_BEGIN,$REGEX_END/p" > "$FILE"

if [ ! -f "$FILE" ]; then
    echo "Failed getting the certificates, no output file was created."
    exit
fi


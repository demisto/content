#!/bin/bash
# This script will generate the X509 cert in both pfx and cer formats, and return the b64 string for authentication
# in O365

echo "This script will return a B64 encoded pfx certificate that should be used in the Certificate parameter of your O365 S&C integration. Please be sure to sign the certificate with a passphrase as this will be necessary for the Certificate Password parameter"
echo -e "Please enter the name for your certificate: "
read -r  cert_name

echo -e "How many days should the certificate be valid?: "
read -r  cert_days
if [[ ! $cert_days =~ ^[0-9]+$ ]] ; then
    echo "Error - valid integer not provided."
    exit
fi

openssl genrsa -out "${cert_name}".pem 2048
openssl req -new -sha256 -key "${cert_name}".pem -out "${cert_name}".csr
openssl req -x509 -sha256 -days "$cert_days" -key "${cert_name}".pem -in "${cert_name}".csr -out "${cert_name}-cert".pem
openssl pkcs12 -export -inkey "${cert_name}".pem -in "${cert_name}-cert".pem -out "${cert_name}-cert".pfx
openssl x509 -inform PEM -in "${cert_name}-cert".pem -outform DER -out "${cert_name}-cert".cer
openssl base64 -in "${cert_name}-cert".pfx -out "${cert_name}-b64-string".txt
echo -e "Please copy the following b64 encoded string and add it to the Certificate parameter: "
cat "${cert_name}-b64-string".txt
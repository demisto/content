#!/bin/sh
openssl genpkey -out client.key -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM
openssl req -key client.key -new -out client.csr -outform PEM
openssl x509 -outform PEM -req -days 365 -in client.csr -signkey client.key -sha256 -out client.crt
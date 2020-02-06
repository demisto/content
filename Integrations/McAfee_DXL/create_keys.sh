openssl genpkey -out client.key -algorithm RSA -pkeyopt rsa_keygen_bits:2048
openssl req -key client.key -new -out client.csr
openssl x509 -req -days 365 -in client.csr -signkey client.key -sha256 -out client.crt
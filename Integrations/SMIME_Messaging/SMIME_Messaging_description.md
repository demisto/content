##  Configure rsa key and certificate
- run command `openssl req -newkey rsa:1024 -nodes -x509 -days 365 -out CERTIFICATE -keyout PRIVATE`

##### where CERTIFICATE is the out public certificate file name. and PRIVATE is the out private key file name.
- copy the text from CERTIFICATE to Public Key field.
- copy the text from PRIVATE to Private Key field.
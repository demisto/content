## RSA Encryption Tools
In order to use this integration enter your own RSA public and/or private keys as parameters for use.

You can create the RSA keys by running the following commands in your terminal:
- `openssl genrsa -des3 -out private.pem 4096`
    - Generates a 4096-bit RSA private key, encrypts it with a password you provide, and writes it to `private.pem`.
- `openssl rsa -in private.pem -outform PEM -RSAPublicKey_out -out public.pem`
    - Generates the public key out of the private key, and writes it to `public.pem`.
- `openssl rsa -in private.pem -out private_unencrypted.pem -outform PEM`
    - Generates the unencrypted version of your private key, and writes it to `private_unencrypted.pem`.

You can read more about those commands here:
- [openssl genrsa](https://www.openssl.org/docs/man1.1.1/man1/openssl-genrsa.html)
- [openssl rsa](https://www.openssl.org/docs/man1.1.1/man1/openssl-rsa.html)

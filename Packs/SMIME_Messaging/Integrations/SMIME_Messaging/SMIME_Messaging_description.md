
## Configure an RSA Key and Certificate

1. Run the following command: `openssl req -newkey rsa:1024 -nodes -x509 -days 365 -out CERTIFICATE -keyout PRIVATE`

   - **CERTIFICATE** is the out public certificate file name. 
   - **PRIVATE** is the out private key file name.
2. Copy the text from CERTIFICATE to the **Public Key** field when configuring the integration instance.
3. copy the text from PRIVATE to **Private Key** field when configuring the integration instance.

## Certificate usage

- Signing emails uses the public/private keys from the instance parameters.
- Email encryption requires the public certificate of the receiver.
  - Provided on command call, use `instancePublicKey` to use the instance params.
- Decrypting emails uses the private key from the instance parameters.
- Verifying emails looks for the certificate in the signed message.
  - A different certificate can be provided if needed.

See [here for more information](https://m2crypto.readthedocs.io/en/latest/howto.smime.html#howto-smime).

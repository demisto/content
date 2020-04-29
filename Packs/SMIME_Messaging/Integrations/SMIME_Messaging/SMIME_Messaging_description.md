
##  Configure an RSA Key and Certificate
1. Run the following command: `openssl req -newkey rsa:1024 -nodes -x509 -days 365 -out CERTIFICATE -keyout PRIVATE`
  - **CERTIFICATE** is the out public certificate file name. 
  - **PRIVATE** is the out private key file name.
2. Copy the text from CERTIFICATE to the **Public Key** field when configuring the integration instance.
3. copy the text from PRIVATE to **Private Key** field when configuring the integration instance.

See [here for more information](https://m2crypto.readthedocs.io/en/latest/howto.smime.html#howto-smime).

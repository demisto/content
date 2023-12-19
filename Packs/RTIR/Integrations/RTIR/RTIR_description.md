**Authentication Methods**
- *Basic Auth* - Authenticates using a Username and Password.
- *Token Auth* - Authenticates using a Token instead of Username and Password.

**Certificate**
If using certificate authentication, add the Certificate and Private Key parameters.
To get the certificate and private key from the PKCS12 (.p12) file:
- On your terminal, run `openssl pkcs12 -clcerts -nokeys -in [your_certificate_name.p12] -out [certificate_name.txt]` to extract the certificate from the .p12 file.
- Open the [certificate_name.txt] file and copy the Certificate (with the title and suffix lines beginning with -----) to the `Certificate` parameter.
- Delete the [certificate_name.txt] file after copying the contents.
- On your terminal, run `openssl pkcs12 -in [your_certificate_name.p12] -nodes -nocerts -out [private_key_name.txt]` to extract the private key from the .p12 file.
- Open the [private_key_name.txt] file and copy the Private Key (with the title and suffix lines beginning with -----) to the `Private Key` parameter.
- Delete the [private_key_name.txt] file after copying the contents.

Additional Parameters:
* Referer (Optional) - Adds a referer header to the requests sent by the integration.

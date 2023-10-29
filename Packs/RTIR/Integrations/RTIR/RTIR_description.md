**Authentication Methods**
- *Basic Auth* - Authenticates using a Username and Password.
- *Token Auth* - Authenticates using a Token instead of Username and Password.

**Certificate**
If using certificate authentication, add the Certificate and Private Key parameters.
To get the certificate and private key from Pkcs12 (.p12) file:
- Run on your terminal `openssl pkcs12 -clcerts -nokeys -in [your_certificate_name.p12] -out [certificate_name.txt]` to extract certificate from .p12 file.
- Open the [certificate_name.txt] file and copy the contents (only the certificate part) to the `Certificate` parameter.
- Delete the [certificate_name.txt] file after copying the contents.
- Run on your terminal `openssl pkcs12 -in [your_certificate_name.p12] -nodes -nocerts -out [private_key_name.txt]` to extract private key from .p12 file.
- Open the [private_key_name.txt] file and copy the contents (only the private key part) to the `Private Key` parameter.
- Deleted the [private_key_name.txt] file after copying the contents.

Additional Parameters:
* Referer (Optional) - Adds a referer header to the requests sent by the integration.

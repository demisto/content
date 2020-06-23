### Using API Token authentication
In order to use the integration with an API token you'll first need to change the `Username / API Key (see '?')` field to `_api_token_key`. Following this step, you can now enter the API Token into the `Password` field - this value will be used as an API key.


### Using custom authentication header
In case the TAXII 2 server you're trying to connect to requires a custom authentication header, 
 you'll first need to change the `Username / API Key (see '?')` field to `_header:` and the custom header name, e.g. `_header:custom_auth`. Following this step, you can now enter the custom auth header value into the Password field - this value will be used as a custom auth header.



as_header:

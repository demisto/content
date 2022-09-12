### Using API Token authentication
In order to use the integration with an API token you'll first need to change the `Username / API Key` field to `_api_token_key`. Following this step, you can now enter the API Token into the `Password` field - this value will be used as an API key.


### Using custom authentication header
In case the TAXII 2 server you're trying to connect to requires a custom authentication header, you'll first need to change the `Username / API Key` field to `_header:` and the custom header name, e.g. `_header:custom_auth`. Following this step, you can now enter the custom authentication header value into the `Password` field - this value will be used as a custom authentication header.

### Complex Observation Mode
Two or more Observation Expressions MAY be combined using a complex observation operator such as "AND", "OR", and "FOLLOWEDBY", e.g. `[ IP = 'b' ] AND [ URL = 'd' ]`. These relationships are not represented in CORTEX XSOAR threat intel management indicators. You can opt to create them while ignoring these relations, or you can opt to ignore these expressions - if you choose to ignore these expressions, then no indicators will be created for complex observations.

Integration with Tanium REST API. Available from Tanium version 7.3.0. You can manage questions, actions, saved questions, packages and sensor information.

## Configuration Parameters

**Hostname**  
The network address of the Tanium server host.

**Domain**  
The Tanium user domain. Relevant when there is more than one domain inside Tanium.

**Credentials**  
The credentials should be the same as the Tanium client.

**API Token**  
The API token that should be used, if using OAuth 2.0 authentication.


## Authentication Process
This integration supports both basic authentication and OAuth 2.0 authentication.

### Basic Authentication
To authenticate using basic authentication fill in the username and password into the corresponding fields and leave
 the API Token field empty. The username and password should be the same as the Tanium client.
 
### OAuth 2.0 Authentication
To use OAuth 2.0 follow the next steps:

1. Follow the instructions [**here**](https://docs.tanium.com/platform_user/platform_user/console_api_tokens.html#add_API_tokens)  to create an API token.

2. Paste the generated API Token into the *API Token* parameter in the instance configuration, and leave the username
 and password fields empty.
3. Click the **Test** button to validate the instance configuration.

**Notes:**
1. **Trusted IP Addresses**: by default, the Tanium Server blocks API tokens from all addresses except registered Tanium
 Module Servers. To add additional allowed IP addresses for any API token, add the IP addresses to the api_token_trusted_ip_address_list global setting. To add allowed IP addresses for an individual API token, specify the IP addresses in the trusted_ip_addresses field of the api_token object.
2. **Expiration Time**: by default, an api_token is valid for seven days. To change the expiration timeframe, edit the
 api_token_expiration_in_days global setting (minimum value is 1), or include a value with the expire_in_days field when you create the token.
3. To edit a global setting in the Tanium platform, go to *Administration* -> *Global Settings* and search for the
 setting you would like to edit.
  
4. For more information see the [**Tanium documentation**](https://docs.tanium.com/platform_user/platform_user/console_api_tokens.html).


---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/tanium-v2)
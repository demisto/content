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
1. Login to the Tanium client and navigate to *Administration* -> *API Tokens*
![image](https://user-images.githubusercontent.com/61732335/119852184-bcf11000-bf17-11eb-8b2f-1d473a20850e.png)
2. Click **New API Token** to create a new API Token.
![image](https://user-images.githubusercontent.com/61732335/119852685-30931d00-bf18-11eb-9889-d8fdafce4554.png)
3. In the pop-up window, modify the expiration time and trusted IP addresses if needed and click save.
![image](https://user-images.githubusercontent.com/61732335/119853343-c9299d00-bf18-11eb-8bb7-a88940508c7e.png)
4. In the next pop-up window, fill in the Tanium credentials and copy the generated API token.
![image](https://user-images.githubusercontent.com/61732335/119853899-4523e500-bf19-11eb-9a49-ec1886a16c0d.png)
Notice! The API Token cannot be copied after closing the window, so make sure to save it for future use.
5. Paste the generated API Token into the *API Token* parameter in the instance configuration, and leave the username
 and password fields empty.
6. Press the **Test** button to validate the instance configuration.

#### Notes:
1. Trusted IP Addresses: by default, the Tanium Server blocks API tokens from all addresses except registered Tanium
 Module Servers. To add additional allowed IP addresses for any API token, add the IP addresses to the api_token_trusted_ip_address_list global setting. To add allowed IP addresses for an individual API token, specify the IP addresses in the trusted_ip_addresses field of the api_token object.
2. Expiration Time: by default, an api_token is valid for seven days. To change the expiration timeframe, edit the
 api_token_expiration_in_days global setting (minimum value is 1), or include a value with the expire_in_days field when you create the token.
3. To edit a global setting in the Tanium platform, go to *Administration* -> *Global Settings* and search for the
 setting you would like to edit.
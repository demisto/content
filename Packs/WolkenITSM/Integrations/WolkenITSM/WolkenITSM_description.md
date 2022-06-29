#### Integration Author: shubgwal1029 (Shubham Agarwal)

***
## Instance Configuration

The integration supports Oauth2.0 authorization.
To use OAuth 2.0 authorization perform the following steps:
1. Input the required parameters - API Key -  Basic {}, Refresh Token, URL,Client ID, Service Account, Domain. 
2. Run the command !wolken-get-access-token from the XSOAR CLI. This step generates access token and saves in the integration context access token and other parameters to the Wolken instance and is required only the first time you configure a new instance in the XSOAR platform.

Notes:
1. When running the !wolken-get-access-token command, refresh token is saved in integration context which will be used to produce new access tokens after the current access token has expired.
2. Every time the refresh token expires you will have to run the !wolken-get-access-token command again. Therefore, we recommend to set the Refresh Token Lifespan field in the endpoint created in step 1 to a long period (can be set to several years).
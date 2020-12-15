In order to use the integration, there are 2 application authentication methods available:

Note: Depending on the authentication method that you use, the integration parameters might change.

#### Cortex XSOAR Azure app

In this method, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

To configure the integration:

1. The ***Application ID*** integration parameter should be set to `8922dd2d-7539-4711-b839-374f86083959` (the Cortex XSOAR Azure app ID).

2. The ***Scope*** integration parameter should be set according to the requested OAuth2 permissions types to grant access to in Microsoft identity platform, for more details see the [Microsoft documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent).

3. The ***Application Secret*** and the ***Tenant ID*** integration parameters should be left blank.

4. Run the *msgraph-api-auth-start* command - you will be prompted to open the page https://microsoft.com/devicelogin and enter the generated code.

5. Run the *msgraph-api-auth-complete* command

6. Run the *msgraph-api-test* command to ensure connectivity to Microsoft. 
 
#### Self Deployed Azure app

For more information, refer to the following [article](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application). 

The ***Application Secret*** and the ***Tenant ID*** integration parameters are required for this method.

The integration supports only Application permission type, and does not support Delegated permission type. 

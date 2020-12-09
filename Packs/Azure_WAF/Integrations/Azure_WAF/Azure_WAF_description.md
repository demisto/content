In order to use the integration, there are 2 application authentication methods available:

Note: Depending on the authentication method that you use, the integration parameters might change.

#### Cortex XSOAR Azure app

In this method, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

To configure the integration:

1. The ***Application ID*** integration parameter should be set to `cf22fd73-29f1-4245-8e16-533704926d20`
 (the Cortex XSOAR Azure app ID).

2. The ***Application Secret*** and the ***Tenant ID*** integration parameters should be left blank.

3. Run the *azure-waf-auth-start* command - you will be prompted to open the page https://microsoft.com/devicelogin and enter the generated code.

4. Run the *azure-waf-auth-complete* command

5. Run the *azure-waf-test* command to ensure connectivity to Microsoft. 

#### Self Deployed Azure app

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have `user_impersonation` permission and must allow public client flows (Can be found under `Authentication` section of the app).

## Authorize Cortex XSOAR for Azure Active Directory Users

You need to grant Cortex XSOAR authorization to access Azure Active Directory Users.

1. Access the [authorization flow](https://oproxy.demisto.ninja/ms-graph-user).
2. Click the **Start Authorization Process** button and you will be prompted to grant Cortex XSOAR permissions for your Azure Active Directory Users.
3. Click the **Accept** button and you will receive your ID, token, and key. You will need to enter these when you configure the Azure Active Directory Users integration instance in Cortex XSOAR.

## Authorize Cortex XSOAR for Azure Active Directory Users (self-deployed configuration)

There are two different authentication methods for self-deployed configuration: [client credentials flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow) and the [authorization code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow).
We recommend using the client credentials one.

In order to use the ***msgraph-user-change-password*** command, you must configure with authorization code flow.

Note: when using the authorization code flow, make sure the user you authenticate with has the right roles in Azure AD in order to use the command.

###Self deployed configuration with client credentials flow
1. Enter your client ID in the ***ID*** parameter field.
2. Enter your client secret in the ***Key*** parameter field.
3. Enter your tenant ID in the ***Token*** parameter field.
   
###Self deployed configuration with authorization code flow
1. Make sure the following permissions are granted for the app registration:
   -  API/Permission name `Directory.AccessAsUser.All` of type `Delegated`
2. Copy the following URL and replace the ***TENANT_ID***, ***CLIENT_ID*** and ***REDIRECT_URI*** with your own client ID and redirect URI, accordingly.
```https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize?response_type=code&scope=offline_access%20directory.accessasuser.all&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI```
3. Enter the link and you will be prompted to grant Cortex XSOAR permissions for your Azure Service Management. You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
4. Copy the ***AUTH_CODE*** (without the “code=” prefix) and paste it in your instance configuration under the **Authorization code** parameter.
5. Enter your client ID in the ***ID*** parameter field.
6. Enter your client secret in the ***Key*** parameter field.
7. Enter your tenant ID in the ***Token*** parameter field.
8. Enter your redirect URI in the ***Redirect URI*** parameter field.

For full integration documentation, see our [reference docs](https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph-user).

The commands: ***msgraph-user-terminate-session***, ***msgraph-user-change-password*** are only supported in a self-deployed application configuration.


## Authorize Cortex XSOAR for Azure Active Directory Users

You need to grant Cortex XSOAR authorization to access Azure Active Directory Users.

1. Access the [authorization flow](https://oproxy.demisto.ninja/ms-graph-user).
2. Click the **Start Authorization Process** button and you will be prompted to grant Cortex XSOAR permissions for your Azure Active Directory Users.
3. Click the **Accept** button and you will receive your ID, token, and key. You will need to enter these when you configure the Azure Active Directory Users integration instance in Cortex XSOAR.

## Authorize Cortex XSOAR for Azure Active Directory Users (self-deployed configuration)

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Make sure the following permissions are granted for the app registration:
   -  API/Permission name `Directory.AccessAsUser.All` of type `Delegated`
3. Copy the following URL and replace the ***TENANT_ID***, ***CLIENT_ID*** and ***REDIRECT_URI*** with your own client ID and redirect URI, accordingly.
```https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize?response_type=code&scope=offline_access%20directory.accessasuser.all&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI```
4. Enter the link and you will be prompted to grant Cortex XSOAR permissions for your Azure Service Management. You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
5. Copy the ***AUTH_CODE*** (without the “code=” prefix) and paste it in your instance configuration under the **Authorization code** parameter.
6. Enter your client ID in the ***ID*** parameter field.
7. Enter your client secret in the ***Key*** parameter field.
8. Enter your tenant ID in the ***Token*** parameter field.
9. Enter your redirect URI in the ***Redirect URI*** parameter field.

### Using National Cloud
Using a national cloud endpoint is supported by setting the *Host URL* parameter to one of the following options:
* US Government GCC-High Endpoint: `https://graph.microsoft.us`
* US Government Department of Defence (DoD) Endpoint: `https://dod-graph.microsoft.us`
* Microsoft 365 Germany Endpoint: `https://graph.microsoft.de`
* Microsoft Operated by 21Vianet Endpoint: `https://microsoftgraph.chinacloudapi.cn`

Please refer to [Microsoft Integrations - Using National Cloud](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#using-national-cloud) for more information.

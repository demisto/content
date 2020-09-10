To allow us access to Microsoft Graph User, an admin has to approve our app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-graph-user).
After authorizing the Demisto app, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields.
## Authorize Cortex XSOAR for Microsoft Graph User

You need to grant Cortex XSOAR authorization to access Microsoft Graph User.

1. Access the [authorization flow](https://oproxy.demisto.ninja/ms-graph-user). 
2. Click the **Start Authorization Process** button and you will be prompted to grant Cortex XSOAR permissions for your Microsoft Graph User. 
3. Click the **Accept** button and you will receive your ID, token, and key. You will need to enter these when you configure the Microsoft Graph User integration instance in Cortex XSOAR.

## Authorize Cortex XSOAR for Microsoft Graph User (self-deployed configuration)

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Make sure the following permissions are granted for the app registration:
   -  API/Permission name `Directory.AccessAsUser.All` of type `Delegated`
3. Copy the following URL and replace the ***CLIENT_ID*** and ***REDIRECT_URI*** with your own client ID and redirect URI, accordingly.
```https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&scope=offline_access%20directory.accessasuser.all&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI```
4. Enter the link and you will be prompted to grant Cortex XSOAR permissions for your Azure Service Management. You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
5. Copy the ***AUTH_CODE*** (without the “code=” prefix) and paste it in your instance configuration under the **Authorization code** parameter. 
6. Enter your client ID in the ***ID*** parameter. 
7. Enter your client secret in the ***Key*** parameter.
8. Enter your tenant ID in the ***Token*** parameter.
9. Enter your redirect URI in the ***Redirect URI*** parameter.
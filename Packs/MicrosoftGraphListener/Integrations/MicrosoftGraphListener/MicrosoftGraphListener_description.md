 To allow us access to Microsoft Graph Mail, you need to approve our app, by clicking on the following [link](https://oproxy.demisto.ninja/ms-graph-mail-listener).
 After authorizing the Demisto app, you will receive an ID, Refresh Token, and Key, which needs to be added to the integration instance configuration's corresponding fields.

## Authorize Cortex XSOAR for Microsoft Graph Mail (self-deployed configuration)

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new MS Graph App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Make sure the following permissions are granted for the app registration:
   -  API/Permission name `openid` of type `Delegated`
   -  API/Permission name `profile` of type `Delegated`
   -  API/Permission name `Mail.ReadWrite` of type `Delegated`
   -  API/Permission name `Mail.Send` of type `Delegated`
   -  API/Permission name `Mail.Read` of type `Delegated`
3. Copy the following URL and replace the ***CLIENT_ID*** and ***REDIRECT_URI*** with your own client ID and redirect URI, accordingly.
```https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=CLIENT_ID&response_type=code&redirect_uri=REDIRECT_URI&scope=offline_access%20mail.readwrite%20mail.send%20user.read%20profile%20openid%20email```
4. Enter the link and you will be prompted to grant Cortex XSOAR permissions for your Azure Service Management. You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
5. Copy the ***AUTH_CODE*** (without the “code=” prefix) and paste it in your instance configuration under the **Authorization code** parameter. 
6. Enter your client ID in the ***ID*** parameter. 
7. Enter your client secret in the ***Key*** parameter.
8. Enter your tenant ID in the ***Token*** parameter.
9. Enter your redirect URI in the ***Redirect URI*** parameter.
10. Enter your Email address from which to fetch incidents in the ***Email Address*** parameter.
To allow us to access Azure Sentinel, you will be required to give us an authorization to access it. This could be achieved by clicking [here](https://oproxy.demisto.ninja/ms-azure-sentinel). As you click the link, press the “Start Authorization Process” button, and you will be prompted to grant us permissions for your Azure Service Management. By clicking the "Accept" button, you will receive your ID, token and key - enter those in your integration configuration to configure your instance.

Alternatively, for a self-deployed configuration, please copy the following URL and replace the CLIENT_ID and REDIRECT_URI with your own client ID and redirect URI, accordingly.
```https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&resource=https://management.core.windows.net&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI```
Enter the link, and you will be prompted to grant us permissions for your Azure Service Management. Then you will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
Copy the AUTH_CODE (without the “code=” prefix) and paste it in your instance configuration under the “Authorization code" parameter. In addition, enter your client ID in the “ID” parameter, your client secret in the “Key” parameter, and your tenant ID under the "Token" parameter.

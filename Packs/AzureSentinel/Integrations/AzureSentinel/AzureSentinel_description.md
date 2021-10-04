Full documentation for this integration is available at our [reference docs](https://xsoar.pan.dev/docs/reference/integrations/azure-sentinel).


## Authorize Cortex XSOAR for Azure Sentinel

You need to grant Cortex XSOAR authorization to access Azure Sentinel.

1. Access the [authorization flow](https://oproxy.demisto.ninja/ms-azure-sentinel). 
2. Click the **Start Authorization Process** button and you will be prompted to grant Cortex XSOAR permissions for your Azure Service Management. 
3. Click the **Accept** button and you will receive your ID, token, and key. You will need to enter these when you configure the Azure Sentinel integration instance in Cortex XSOAR.

## Authorize Cortex XSOAR for Azure Sentinel (self-deployed configuration)

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Make sure the following permissions are granted for the app registration:
   -  API/Permission name `user_impersonation` of type `Delegated`
3. Copy the following URL and replace the ***CLIENT_ID*** and ***REDIRECT_URI*** with your own client ID and redirect URI, accordingly.
```https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&resource=https://management.core.windows.net&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI```
4. Enter the link and you will be prompted to grant Cortex XSOAR permissions for your Azure Service Management. You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
5. Copy the ***AUTH_CODE*** (without the “code=” prefix) and paste it in your instance configuration under the **Authorization code** parameter. 
6. Enter your client ID in the ***ID*** parameter. 
7. Enter your client secret in the ***Key*** parameter.
8. Enter your tenant ID in the ***Token*** parameter.
9. Enter your redirect URI in the ***Redirect URI*** parameter.

## Get the additional instance parameters

To get the ***Subscription ID***, ***Workspace Name*** and ***Resource Group*** parameters, navigate in the Azure Portal to ***Azure Sentinel > YOUR-WORKSPACE > Settings*** and click on ***Workspace Settings*** tab.

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

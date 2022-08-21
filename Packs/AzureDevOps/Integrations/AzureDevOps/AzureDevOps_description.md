### Authenticating
In order to connect to the Azure DevOps, please follow  these steps:

1. In the Azure Portal, add a new Azure App Registration. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Add the following permissions to your registered app:
   - `Azure DevOps/user_impersonation`
   - `Microsoft Graph/User.Read`
3. In your registered app - Get the Application (client) ID. 
   1. In the Azure Portal, navigate to **App registrations** > your registered application > **Overview**.
   2. Copy and save the Application (client) ID.
4. In the *Client ID* parameter, enter your registered app Application (client) ID.
5. In the *Organization* parameter, enter the Azure DevOps organization name.
   More information about creating an organization or project can be found here:
   
   [Create an organization](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/create-organization?view=azure-devops)

    [Create a project](https://docs.microsoft.com/en-us/azure/devops/organizations/projects/create-project?view=azure-devops&tabs=preview-page)

In order to connect to the Azure DevOps Account, use on of the following flows-

**Client Credentials Flow**(Recommended).

Follow these steps for a User-Authentication configuration:
   1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
   2. choose the 'User Auth' option in the ***Authentication Type*** parameter.
   3. Enter your Client/Application ID in the ***Application ID*** parameter. 
   4. Enter your Client Secret in the ***Client Secret*** parameter.
   5. Enter your Tenant ID in the ***Tenant ID*** parameter.
   6. Enter your Application redirect URI in the ***Application redirect URI*** parameter.
   7. Enter your Authorization code in the ***Authorization code*** parameter.
   8. Save the instance.
   9. Run the ***!azure-devops-auth-test*** command - a 'Success' message should be printed to the War Room.

**Device Code Flow**

use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).
   1. Fill in the required parameters.
   2. Run the ***!azure-devops-auth-start*** command.
   3. Follow the instructions that appear.
   4. Run the ***!azure-devops-auth-complete*** command.
   
    
### Testing authentication and connectivity
To test your authentication and connectivity to the Azure DevOps service run the ***!azure-devops-auth-test*** command.

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

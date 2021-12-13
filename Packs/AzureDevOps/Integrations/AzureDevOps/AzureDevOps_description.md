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
6. In order to connect to the Azure DevOps Account, use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).
   1. Fill in the required parameters.
   2. Run the ***!azure-devops-auth-start*** command.
   3. Follow the instructions that appear.
   4. Run the ***!azure-devops-auth-complete*** command.
    
### Testing authentication and connectivity
To test your authentication and connectivity to the Azure DevOps service run the ***!azure-devops-auth-test*** command.

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

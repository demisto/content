In order to connect to the Azure DevOps, please follow  these steps:


1. You have to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
   Then, add the following permisions:
       <ul>
      <li>Azure DevOps/user_impersonation</li>
      <li>Microsoft Graph/User.Read</li>
    </ul> </li>
2. In your registered app - Get the Application (client) ID. 
   1. Navigate in the Azure Portal to **App registrations** > your registered application > **Overview**.
   2. Copy and save the Application (client) ID.
3. In the ***Client ID*** parameter, enter your registered app Application (client) ID.
4. In the ***Organization*** parameter, enter the Azure DevOps organization name.
   More information about creating an organization or project can be found here:
   
   [Create an organization](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/create-organization?view=azure-devops)

    [Create a project](https://docs.microsoft.com/en-us/azure/devops/organizations/projects/create-project?view=azure-devops&tabs=preview-page)
6. In order to connect to the Azure DevOps Account ,the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.
   - Fill in the required parameters.
   - Run the ***!azure-devops-auth-start*** command. .
   - Follow the instructions that appear.
   - Run the ***!azure-devops-auth-complete*** command.
    
At the end of the process you'll see a message that you've logged in successfully.

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

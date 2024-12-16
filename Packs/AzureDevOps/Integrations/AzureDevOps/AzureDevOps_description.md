In order to connect to the Azure DevOps using the Self-Deployed Azure App, use one of the following methods:

- *Authorization Code Flow* (Recommended).
- *Device Code Flow*.
- *Client Credentials Flow*.

## Self-Deployed Azure App

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
To add the registration, refer to the following [Microsoft article](https://learn.microsoft.com/en-us/defender-xdr/api-create-app-web?view=o365-worldwide) steps 1-8.
1. Add the following permissions to your registered app:
   - `Azure DevOps/user_impersonation`
   - `Microsoft Graph/User.Read`
  To add a permission:
   a. Navigate to **Azure Portal > **Home** > **App registrations**.
   b. Search for your app under 'all applications'.
   c. Click **API permissions** > **Add permission**.
   d. Search for the specific Microsoft API and select the specific permission of type Delegated.
   e. Click **Grant admin consent**.
1. In your registered app - Get the Application (client) ID. 
   a. In the Azure Portal, navigate to **App registrations** > your registered application > **Overview**.
   b. Copy and save the Application (client) ID.
2. In the *Client ID* parameter, enter your registered app Application (client) ID.
3. In the *Organization* parameter, enter the Azure DevOps organization name.
   More information about creating an organization or project can be found here:
   
    [Create an organization](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/create-organization?view=azure-devops)

    [Create a project](https://docs.microsoft.com/en-us/azure/devops/organizations/projects/create-project?view=azure-devops&tabs=preview-page)

To the Azure DevOps Account, use one of the following flows-

## Authorization Code Flow(Recommended).

For a Authorization Code configuration:

   1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
   2. In the *Authentication Type* field, select the **Authorization Code** option.
   3. In the **Application ID** field, enter your Client/Application ID. 
   4. In the **Client Secret** field, enter your Client Secret.
   5. In the **Tenant ID** field, enter your Tenant ID .
   6. In the **Application redirect URI** field, enter your Application redirect URI.
   7. Save the instance.
   8. Run the `!azure-devops-generate-login-url` command in the War Room and follow the instruction.
   9. Run the ***!azure-devops-auth-test*** command - a 'Success' message should be printed to the War Room.


## Device Code Flow

To use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

   1. In the **Application ID** field, enter your Client/Application ID.
   2. Run the ***!azure-devops-auth-start*** command.
   3. Follow the instructions that appear.
   4. Run the ***!azure-devops-auth-complete*** command.
   

## Client Credentials Flow

Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)
*Note:* In the *Select members* section, assign the application you created earlier.
To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
   1. In the **Authentication Type** field, select the **Client Credentials** option.
   2. In the **Application ID** field, enter your Client/Application ID.
   3. In the **Tenant ID** field, enter your Tenant ID .
   4. In the **Client Secret** field, enter your Client Secret.
   5. Click **Test** to validate the URLs, token, and connection
   6. Save the instance.
    
### Testing authentication and connectivity
If you are using Device Code Flow or Authorization Code Flow, for testing your authentication and connectivity to the Azure DevOps service run the ***!azure-devops-auth-test*** command. 

If you are using Client Credentials Flow, click **Test** when you are configuring the instance.

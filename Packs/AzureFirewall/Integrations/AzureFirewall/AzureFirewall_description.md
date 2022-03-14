### Authenticating
In order to connect to the Azure Firewall, please follow  these steps:

1. In the Azure Portal, add a new Azure App Registration. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Add the following permissions to your registered app:
   - `Azure Service Management/user_impersonation`
   - `Microsoft Graph/User.Read`
3. In your registered app - Get the Application (client) ID. 
   1. In the Azure Portal, navigate to **App registrations** > your registered application > **Overview**.
   2. Copy and save the Application (client) ID.
4. In the *Client ID* parameter, enter your registered app Application (client) ID.

#### Get Subscription ID and the Resource Group values

1. In the Azure portal, select Resource groups.
2. Select your resource group name.
3. Copy the Subscription ID and enter it in the Subscription ID parameter.
4. Copy your resource group name and enter it in the Resource Group Name parameter.

### Testing authentication and connectivity

In order to connect to the Azure firewall Integration, use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).
   1. Fill in the required parameters.
   2. Run the ***!azure-firewall-auth-start*** command.
   3. Follow the instructions that appear.
   4. Run the ***!azure-firewall-auth-complete*** command.
    

To test your authentication and connectivity to the Azure Firewall service run the ***!azure-firewall-auth-test*** command.

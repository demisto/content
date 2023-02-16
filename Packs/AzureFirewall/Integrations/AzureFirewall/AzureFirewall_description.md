## Authenticating
In order to connect to the Azure Firewall, follow these steps:

1. In the Azure Portal, add a new Azure App Registration. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Add the following permissions to your registered app:
   - `Azure Service Management/user_impersonation`
   - `Microsoft Graph/User.Read`
3. In your registered app - Get the Application (client) ID. 
   1. In the Azure Portal, navigate to **App registrations** > your registered application > **Overview**.
   2. Copy and save the Application (client) ID.
4. In the *Client ID* parameter, enter your registered app Application (client) ID.

### Self-Deployed Authentication

To authenticate using the self-deployed method, provide the following parameters:

- Token - Tenant ID
- Key - Client Secret
   - Alternatively, instead of providing the Client Secret you can authenticate using certificate credentials by providing:
      - Certificate Thumbprint - The certificate thumbprint as appears when registering the certificate to the app.
      - Private Key - The private key of the registered certificate.  

### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**
   2. Select your User Assigned Managed Identity -> copy the Client ID -> put it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For information about Azure Managed Identities see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)

## Get Subscription ID and the Resource Group Values

1. In the Azure portal, select **Resource groups**.
2. Select your resource group name.
3. Copy the subscription ID and enter it in the *Subscription ID* parameter.
4. Copy your resource group name and enter it in the *Resource Group Name* parameter.

### Testing authentication and connectivity

In order to connect to the Azure firewall integration, use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).
   1. Fill in the required parameters.
   2. Run the ***!azure-firewall-auth-start*** command.
   3. Follow the instructions that appear.
   4. Run the ***!azure-firewall-auth-complete*** command.


To test your authentication and connectivity to the Azure Firewall service run the ***!azure-firewall-auth-test*** command.

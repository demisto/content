In order to connect to the Azure Firewall using either Cortex XSOAR Azure App or the Self-Deployed Azure App, use one of the following methods:

- *Device Code Flow*.
- *Azure Managed Identities*
- *Client Credentials Flow*.

## Required Permissions:
1. user_impersonation
2. user.read 


## Authentication Using the Device Code Flow

1. In the Azure Portal, add a new Azure App Registration. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Add the following permissions to your registered app:
   - `Azure Service Management/user_impersonation`
   - `Microsoft Graph/User.Read`
4. In your registered app - Get the Application (client) ID. 
   1. In the Azure Portal, navigate to **App registrations** > your registered application > **Overview**.
   2. Copy and save the Application (client) ID.
5. In the *Client ID* parameter, enter your registered app Application (client) ID.

### Testing authentication and connectivity

In order to connect to the Azure firewall integration, use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).
   1. Fill in the required parameters.
   2. Run the ***!azure-firewall-auth-start*** command.
   3. Follow the instructions that appear.
   4. Run the ***!azure-firewall-auth-complete*** command.

#### Cortex XSOAR Azure app
In order to use the Cortex XSOAR Azure application, use the default application ID (cf22fd73-29f1-4245-8e16-533704926d20) and fill in your subscription ID and default resource group name.

# Self-Deployed Application
To use a self-configured Azure application, you need to add a [new Azure App Registration in the Azure Portal](https://docs.microsoft.com/en-us/graph/auth-register-app-v2#register-a-new-application-using-the-azure-portal).

## Client Credentials Flow Authentication

Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

*Note:* In the *Select members* section, assign the application you created earlier.

To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
1. In the **Application ID** field, enter your Client/Application ID.
2. In the **Tenant ID** field, enter your Tenant ID .
3. In the **Client Secret** field, enter your Client Secret.
4. Click **Test** to validate the URLs, token, and connection
5. Save the instance.

*Note:* instead of providing the Client Secret you can authenticate using certificate credentials by providing:
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

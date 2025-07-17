In order to connect to the Azure Firewall use one of the following methods:

- *Client Credentials Flow*
- *Device Code Flow*
- *Azure Managed Identities Flow*

## Self-Deployed Azure App

Before you connect to Azure Firewall, if using a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

To add the registration, refer to the following [Microsoft article](https://learn.microsoft.com/en-us/defender-xdr/api-create-app-web?view=o365-worldwide) steps.

### Required permissions

- Azure Service Management - permission: `user_impersonation` of type Delegated
- Microsoft Graph - permission: `User.Read` of type Delegated

To add a permission:

1. Navigate to **Home** > **App registrations**.
2. Search for your app under 'all applications'.
3. Click **API permissions** > **Add permission**.
4. Search for the specific Microsoft API and select the specific permission of type Delegated.

### Authentication Using the Client Credentials Flow

Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal).
*Note:* In the *Select members* section, assign the application you created earlier.
To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
1. In the **Client ID** field, enter your Client/Application ID.
2. In the **Tenant ID** field, enter your Tenant ID .
3. In the **Client Secret** field, enter your Client Secret.
4. Click **Test** to validate the URLs, token, and connection
5. Save the instance.

*Note:* instead of providing the Client Secret you can authenticate using certificate credentials by providing:
- Certificate Thumbprint - The certificate thumbprint as appears when registering the certificate to the app.
- Private Key - The private key of the registered certificate.  

### Authentication Using the Device Code Flow

Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow).

In order to connect to the Azure Firewall using either Cortex XSOAR Azure App or the Self-Deployed Azure App:

1. Fill in the required parameters.
2. Run the ***!azure-firewall-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!azure-firewall-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (f5b37a76-f937-4c57-a9b5-31dab1c7e236).

You only need to fill in your subscription ID and resource group name.

### Azure Managed Identities Flow
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
3. Copy the subscription ID and resource group name 
4. In XSOAR add the Subscription ID and Resource Group Name parameter from step 3.



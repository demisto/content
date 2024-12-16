In order to connect to the AzureWAF using either Cortex XSOAR Azure App or the Self-Deployed Azure App, use one of the following methods:

- *Authorization Code Flow* (Recommended).
- *Device Code Flow*.
- *Azure Managed Identities*
- *Client Credentials Flow*.
  
# Self-Deployed Application
To use a self-configured Azure application, you need to add a [new Azure App Registration in the Azure Portal](https://docs.microsoft.com/en-us/graph/auth-register-app-v2#register-a-new-application-using-the-azure-portal).

## Required Permissions:
1. user_impersonation
2. offline_access
3. user.read 

## Authentication Using the User-Authentication Flow (recommended)

Follow these steps for a User-Authentication configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. choose the 'User Auth' option in the ***Authentication Type*** parameter.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Client Secret*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.
6. Enter your Application redirect URI in the ***Application redirect URI*** parameter.
7. Save the instance.
8. Run the `!azure-waf-generate-login-url` command in the War Room and follow the instruction.
9. Run the ***!azure-waf-auth-test*** command - a 'Success' message should be printed to the War Room.
 

### Authentication Using the Device Code Flow
Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Azure SQL Management with Cortex XSOAR.

In order to connect to Azure Web Application Firewall using either the Cortex XSOAR Azure or Self Deployed Azure application:
1. Fill in the required parameters
2. choose the 'Device' option in the ***user_auth_flow*** parameter.
4. Run the ***!azure-waf-auth-start*** command.
4. Follow the instructions that appear.
5. Run the ***!azure-waf-auth-complete*** command.
At end of the process, you will see a message that you logged in successfully.

#### Cortex XSOAR Azure app
In order to use the Cortex XSOAR Azure application, use the default application ID (cf22fd73-29f1-4245-8e16-533704926d20) and fill in your subscription ID and default resource group name.

# Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - In the **Authentication Type** drop-down list, select **Azure Managed Identities** and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities client id** field in the instance configuration.
   3. In the **Authentication Type** drop-down list, select **Azure Managed Identities**.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).

## Client Credentials Flow Authentication

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
If you are using Device Code Flow or Authorization Code Flow, for testing your authentication and connectivity to the Azure AzureWAF service run the ***!azure-waf-auth-test*** command.
If you are using Client Credentials Flow, click **Test** when you are configuring the instance.
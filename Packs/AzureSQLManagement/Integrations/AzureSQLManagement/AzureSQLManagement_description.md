Microsoft Azure SQL Management Integration manages the Auditing and Threat Policies for Azure SQL.

# Self-Deployed Application
To use a self-configured Azure application, you need to add a [new Azure App Registration in the Azure Portal](https://docs.microsoft.com/en-us/graph/auth-register-app-v2#register-a-new-application-using-the-azure-portal).

The application must have *user_impersonation* permission and must allow public client flows (found under the **Authentication** section of the app). And must allow public client flows (found under the **Authentication** section of the app) for Device-code based authentications.

## Authentication Using the User-Authentication Flow (recommended)

Follow these steps for a User-Authentication configuration:

1. To use a self-configured Azure application, add a new Azure App Registration in the Azure Portal. To add the registration, see this [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app), steps 1-8.
2. Choose the 'User Auth' option in the *Authentication Type* parameter.
3. Enter your Client/Application ID in the *Application ID* parameter. 
4. Enter your Client Secret in the *Client Secret* parameter.
5. Enter your Tenant ID in the *Tenant ID* parameter.
6. Enter your Application redirect URI in the *Application redirect URI* parameter.
8. Save the instance.
9. Run the ***!azure-sql-generate-login-url*** command in the War Room and follow the instruction.
10. Run the **!azure-sql-auth-test*** command - a 'Success' message should be printed to the War Room.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (8f9010bb-4efe-4cfa-a197-98a2694b7e0c).

You only need to fill in your subscription ID and resource group name. You can find your resource group and 
subscription ID in the Azure Portal. For a more detailed explanation, visit [this page](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#azure-integrations-params).

### Authentication Using the Device Code Flow
Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Azure SQL Management with Cortex XSOAR.

Follow these steps for a self-deployed configuration:
1. Fill in the required parameters.
2. choose the 'Device' option in the ***user_auth_flow*** parameter.
3. Run the ***!azure-sql-auth-start*** command. 
4. Follow the instructions that appear.
5. Run the ***!azure-sql-auth-complete*** command.

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - In the **Authentication Type** drop-down list, select **Azure Managed Identities**  and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities client ID** field in the instance configuration.
   3. In the **Authentication Type** drop-down list, select **Azure Managed Identities**.

For information about Azure Managed Identities see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)

### Device Code Flow
In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

To connect to Microsoft Graph Identity & Access using either Cortex XSOAR Graph app or the Self-Deployed Graph app:
1. Fill in the required parameters.
2. Run the ***!msgraph-identity-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!msgraph-identity-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Graph App

To use the Cortex XSOAR Azure application, use the default application ID (597c0375-766f-4e6d-ad2a-f48117044ac5).  
A detailed explanation on how to register an app can be found [here](https://docs.microsoft.com/en-us/power-apps/developer/data-platform/walkthrough-register-app-azure-active-directory).

#### Self-Deployed Graph App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with 
mobile and desktop flows enabled.

### Client Credentials Flow
___
Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration.
2. Enter your Client/Application ID in the ***Application ID*** parameter. 
3. Enter your Client Secret in the ***Client Secret*** parameter.
4. Enter your Tenant ID in the ***Tenant ID*** parameter.

### Required Permissions
RoleManagement.ReadWrite.Directory - Application

### Azure Managed Identities Authentication
___
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).



## Configure Azure Risky Users on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureRiskyUsers.
3. Click **Add instance** to create and configure a new integration instance.

## Authorization

### Authentication Using the Client Credentials Flow (recommended)

Follow these steps for a **self-deployed configuration**:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. Select the **client-credentials** Authentication Type.
3. Enter your Client/Application ID in the *Application ID* parameter. 
4. Enter your Client Secret in the *Client Secret* parameter.
5. Enter your Tenant ID in the *Tenant ID* parameter.
6. Save the instance.
7. Run the ***!azure-risky-users-auth-test*** command - a 'Success' message should be printed to the war-room.


### Authentication Using the Device Flow
[Device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

In order to connect to Microsoft Risky User using either **Cortex XSOAR App** or the **Self-Deployed App**:
1. Fill in the required parameters.
2. Run the ***!msgraph-identity-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!msgraph-identity-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.
In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, 
use the Client ID - (application_id) (***ec854987-95fa-4c8f-8056-768dd0f409ac***).

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.

### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - In the **Authentication Type** drop-down list, select **Azure Managed Identities** and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities client ID** field in the instance configuration.
   3. In the **Authentication Type** drop-down list, select **Azure Managed Identities**.

For information about Azure Managed Identities see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)


#### Required Permissions
*Make sure to provide the following permissions for the app to work with Azure Risky Users:*
 - ***IdentityRiskyUser.Read.All*** - https://docs.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0
 - ***IdentityRiskEvent.Read.All*** - https://docs.microsoft.com/en-us/graph/api/riskdetection-get?view=graph-rest-1.0
 - ***IdentityRiskEvent.ReadWrite.All***
 - ***IdentityRiskyUser.ReadWrite.All***
 - ***User.Read***
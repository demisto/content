## Authorization
To use Microsoft Graph Services, you need to configure authentication. There are three authentication methods available:
- Client Credentials Flow (Recommended)
- Device Code Flow
- Azure Managed Identities


### Client Credentials Flow (Recommended)
___
Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure app registration in the Azure portal. To add the registration, see this [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the instance configuration, under the **Authentication Type** field select the **Client Credentials** option.
3. Enter your Client/Application ID in the **Application ID** parameter. 
4. Enter your Client Secret in the **Password** parameter.
5. Enter your Tenant ID in the **Tenant ID** parameter.
6. Run the ***!msgraph-apps-auth-test*** command to test the connection and the authorization process.


### Device Code Flow
___

Use the [device code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
to link Microsoft Graph Services with Cortex XSOAR.

To connect to Microsoft Graph Services using either the Cortex XSOAR Azure app or the self-deployed Azure app:
1. In the instance configuration, under the **Authentication Type** field select the **Device** option.
2. Fill in the required parameters.
3. Run the ***!msgraph-apps-auth-start*** command.
4. Follow the instructions that appear.
5. Run the ***!msgraph-apps-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

To use the Cortex XSOAR Azure application, use the default application ID (6b071e63-f701-454b-9e54-ede4c96483e6).

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure app registration in the Azure portal, with mobile and desktop flows enabled.

### Azure Managed Identities Authentication
___
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - In the **Authentication Type** drop-down list, select **Azure Managed Identities**  and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities client id** field in the instance configuration.
   3. In the **Authentication Type** drop-down list, select **Azure Managed Identities**.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)

----

#### Required Permissions
Application.ReadWrite.All - Application

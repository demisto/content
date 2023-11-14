## Authorization
##### There are three ways to authenticate to the Microsoft Graph Services:
1. *Client Credentials Flow* (Recommended).
2. *Device Code Flow*.
3. *Azure Managed Identities*.


### Client Credentials Flow (Recommended)
___
Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the instance configuration, under the ***Authentication Type*** field select the ***Client Credentials*** option.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Password*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.
6. Run the ***!msgraph-apps-auth-test*** command to test the connection and the authorization process.


### Device Code Flow
___

Use the [device code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
to link Microsoft Graph Services with Cortex XSOAR.

In order to connect to Microsoft Graph Services using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. In the instance configuration, under the ***Authentication Type*** field select the ***Device*** option.
3. Fill in the required parameters.
4. Run the ***!msgraph-apps-auth-start*** command.
5. Follow the instructions that appear.
6. Run the ***!msgraph-apps-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.
In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (3307a0ab-612c-47af-b3b5-8208247562db).

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.



### Azure Managed Identities Authentication
___
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select *Azure Managed Identities* in *Authentication Type* drop-down list and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**
   2. Select your User Assigned Managed Identity -> copy the Client ID -> put it in the ***Azure Managed Identities client id*** filed in the instance configuration.
   3. Select *Azure Managed Identities* in **Authentication Type** drop-down list.

For information about Azure Managed Identities see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)

# Required Permissions
* Group.ReadWrite.All - Application
* Team.ReadBasic.All - Application
* TeamMember.ReadWrite.All - Application

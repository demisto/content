In order to connect to the Azure Network Security Groups use one of the following methods:

1. *Authorization Code Flow* (Recommended).
2. *Device Code Flow*.
3. *Azure Managed Identities Flow*.

### Authentication Using the Authorization Code Flow (recommended)

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the **Authentication Type** field, select the **Authorization Code** option.
3. In the **Application ID** field, enter your Client/Application ID. 
4. In the **Client Secret** field, enter your Client Secret.
5. In the **Tenant ID** field, enter your Tenant ID .
6. In the **Application redirect URI** field, enter your Application redirect URI.
7. Save the instance.
8. Run the `!azure-nsg-generate-login-url` command in the War Room and follow the instruction.

### Authentication Using the Device Code Flow

Use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

In order to connect to the Azure Network Security Group using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!azure-nsg-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!azure-nsg-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully. 

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (d4736600-e3d5-4c97-8e65-57abd2b979fe).

You only need to fill in your subscription ID and resource group name. 

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have *user_impersonation* permission and must allow public client flows (can be found under the **Authentication** section of the app).

### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - In the **Authentication Type** drop-down list, select **Azure Managed Identities**  and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities client ID** field in the instance configuration.
   3. In the **Authentication Type** drop-down list, select **Azure Managed Identities**.

For information about Azure Managed Identities see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)

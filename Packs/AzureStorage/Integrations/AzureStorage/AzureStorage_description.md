In order to connect to the Azure Storage Accounts and the Blob Service use either the Cortex XSOAR Azure App or the Self-Deployed Azure App.
Use one of the following methods:

1. *Authorization Code Flow* (Recommended).
2. *Client Credentials Flow*
3. *Device Code Flow*

## Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

To add the registration, refer to the following [Microsoft article](https://learn.microsoft.com/en-us/defender-xdr/api-create-app-web?view=o365-worldwide) steps 1-8.

### Required permissions

- Azure Service Management - permission `user_impersonation` of type Delegated
- Microsoft Graph - permission `offline_access` of type Delegated

To add a permission:

1. Navigate to **Home** > **App registrations**.
2. Search for your app under 'all applications'.
3. Click **API permissions** > **Add permission**.
4. Search for the specific Microsoft API and select the specific permission of type Delegated.

### Authentication Using the Authorization Code Flow (recommended)

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the *Authentication Type* field, select the **Authorization Code** option.
3. In the *Application ID* field, enter your Client/Application ID.
4. In the *Client Secret* field, enter your Client Secret.
5. In the *Tenant ID* field, enter your Tenant ID .
6. In the *Application redirect URI* field, enter your Application redirect URI.
7. Save the instance.
8. Run the `!azure-storage-generate-login-url` command in the War Room and follow the instruction.

### Authentication Using the Client Credentials Flow

1. Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

   *Note:* At the 'Select members' section, assign the application you created before.

2. To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:

   a. In the **Authentication Type** field, select the **Client Credentials** option.

   b. In the **Application ID** field, enter your Client/Application ID.

   c. In the **Subscription ID** field, enter your Subscription ID.

   d. In the **Resource Group Name** field, enter you Resource Group Name.

   e. In the **Tenant ID** field, enter your Tenant ID.

   f. In the **Client Secret** field, enter your Client Secret.

   g. Click **Test** to validate the URLs, token, and connection

   h. Save the instance.


### Authentication Using the Device Code Flow

Use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

1. Fill in the required parameters.
2. Run the ***!azure-storage-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!azure-storage-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (55f9764e-300a-474a-a2bb-549cece85439).

You only need to fill in your subscription ID and resource group name. For more details, follow [Azure Integrations Parameters](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#azure-integrations-params).

#### Self-Configured Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have *user_impersonation* permission and must allow public client flows (can be found under the **Authentication** section of the app).

### Azure Managed Identities Authentication

##### Note: This option is relevant only if the integration is running on Azure VM.

Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
    - In the *Authentication Type* drop-down list, select **Azure Managed Identities** and leave the *Azure Managed Identities Client ID* field empty.

- ##### To use User Assigned Managed Identity
    1. Go to [Azure Portal](https://portal.azure.com/) > **Managed Identities**
    2. Select your User Assigned Managed Identity > copy the Client ID and paste it in the *Azure Managed Identities client ID* field in the instance configuration.
    3. In the *Authentication Type* drop-down list, select **Azure Managed Identities**.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).

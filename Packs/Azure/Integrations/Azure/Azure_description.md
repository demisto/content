Connect to Azure using one of the following authentication methods:

- Client Credentials flow (recommended).
- Authorization Code flow.
- Device Code flow.
- Azure Managed Identities flow.

## Self-Deployed Azure App

To use a self-configured Azure application, add a new Azure App Registration in the Azure Portal.

To add the registration, refer to the following [Microsoft article](https://learn.microsoft.com/en-us/defender-xdr/api-create-app-web?view=o365-worldwide) steps 1-8.

### Required permissions

- Azure Service Management - permission `user_impersonation` of type Delegated
- Microsoft Graph - permission `offline_access` of type Delegated

To add a permission:

1. Navigate to **Home** > **App registrations**.
2. Search for your app under 'all applications'.
3. Click **API permissions** > **Add permission**.
4. Search for the specific Microsoft API and select the specific permission of type Delegated.

### Authentication Using the Client Credentials Flow

Configure an instance that uses this flow with a self-deployed Azure application.  


1. Assign Azure roles in the Azure portal. For more information, see the [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal).

   *Note:* In the *Select members* section, assign the application you created earlier.

2. In the integration instance settings, configure the following:
   1. In the **Authentication Type** field, select the *Client Credentials* option.
   2. In the **Application ID** field, enter your client/application ID.
   3. In the **Default Subscription ID** field, enter your subscription ID.
   4. In the **Default Resource Group Name** field, enter your resource group name.
   5. In the **Tenant ID** field, enter your tenant ID.
   6. In the **Client Secret** field, enter your client secret.
   7. Click **Test** to validate the URLs, token, and connection.
   8. Save the instance.

### Authentication Using the Authorization Code Flow

1. In the **Authentication Type** field, select the *Authorization Code* option.
2. In the **Application ID** field, enter your client/application ID.
3. In the **Client Secret** field, enter your client secret.
4. In the **Tenant ID** field, enter your tenant ID.
5. In the **Application redirect URI** field, enter your application redirect URI.
6. Save the instance.
7. Run the ***!azure-generate-login-url*** command in the War Room and follow the instructions to obtain the authorization code.
8. Paste the value you received in the *Authorization code* parameter and save the instance again.
9. Click **Test** to validate the connection.

### Authentication Using the Device Code Flow

Use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

1. In the **Authentication Type** field, select the *Device Code* option.
2. Fill in the **Application ID**, **Tenant ID**, **Default Subscription ID**, and **Default Resource Group Name** fields.
3. Save the instance.
4. Run the ***!azure-auth-start*** command.
5. Follow the instructions that appear.
6. Run the ***!azure-auth-complete*** command.
7. At the end of the process you will see a message that you have logged in successfully.
8. Run the ***!azure-auth-test*** command to validate the connection. (instead of the **Test** button.)

### Azure Managed Identities Authentication

**Note:** This option is relevant only if the integration is running on an Azure VM. Authenticate using either a system-assigned managed identity or a user-assigned managed identity.

For authentication using a system-assigned managed identity:

1. In the **Authentication Type** drop-down list, select *Azure Managed Identities* and leave the **Azure Managed Identities Client ID** field empty.
2. Click **Test** to validate the connection.

For authentication using a user-assigned managed identity:

1. Go to the Azure Portal > **Managed Identities**.
2. Select your user-assigned managed identity, then copy the client ID and paste it in the **Azure Managed Identities Client ID** field in the instance configuration.
3. In the **Authentication Type** drop-down list, select *Azure Managed Identities*.
4. Click **Test** to validate the connection.
Click **Test** to validate the connection.

More about Microsoft Integrations - Authentication Flows, See here: https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows
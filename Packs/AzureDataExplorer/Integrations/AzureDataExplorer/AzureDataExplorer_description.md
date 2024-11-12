In order to connect to the Azure Data Explorer using either Cortex XSOAR Azure App or the Self-Deployed Azure App, use one of the following methods:

1. *Authorization Code Flow* (Recommended).
2. *Device Code Flow*.
3. *Client Credentials Flow*.

## Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
To add the registration, refer to the following [Microsoft article](https://learn.microsoft.com/en-us/defender-xdr/api-create-app-web?view=o365-worldwide) steps 1-8.

### Required permissions

- Azure Data Explorer - permission `user_impersonation` of type Delegated.
- Microsoft Graph - permission `offline_access` of type Delegated.

To add a permission:

1. Navigate to **Azure Portal > **Home** > **App registrations**.
2. Search for your app under 'all applications'.
3. Click **API permissions** > **Add permission**.
4. Search for the specific Microsoft API and select the specific permission of type Delegated.

### Authentication Using the Authorization Code Flow (recommended)

1. In the *Authentication Type* field, select the **Authorization Code** option.
2. In the *Application ID* field, enter your Client/Application ID. 
3. In the *Client Secret* field, enter your Client Secret.
4. In the *Tenant ID* field, enter your Tenant ID .
5. In the *Application redirect URI* field, enter your Application redirect URI.
6. Save the instance.
7. Run the `!azure-data-explorer-generate-login-url` command in the War Room and follow the instructions.
8. Save the instance.
   
### Authentication Using the Device Code Flow

Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Azure Data Explorer with Cortex XSOAR.

1. Fill in the required parameters.
2. In the **Authentication Type** field, select the **Device Code** option.
3. Run the ***!azure-data-explorer-auth-start*** command.
4. Follow the instructions that appear.
5. Run the ***!azure-data-explorer-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (a9ce8db2-847a-46af-9bfb-725d8a8d3c53).

### Authentication Using the Client Credentials Flow

1. Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

   *Note:* In the *Select members* section, assign the application you created earlier.

2. To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
   a. In the *Authentication Type* field, select the **Client Credentials** option.
   b. In the *Application ID* field, enter your Client/Application ID.
   e. In the *Tenant ID* field, enter your Tenant ID .
   f. In the *Client Secret* field, enter your Client Secret.
   g. Click **Test** to validate the URLs, token, and connection
   h. Save the instance.




### Get the additional instance parameters

To get the ***Cluster URL*** parameter navigate in the Azure Portal to ***Azure Data Explorer Clusters*** > YOUR-CLUSTER and copy ***URI*** tab.

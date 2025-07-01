In order to connect to the Azure integration use the following method:

### Required permissions

- Azure Service Management - permission `user_impersonation` of type Delegated
- Microsoft Graph - permission `offline_access` of type Delegated

To add a permission:

1. Navigate to **Home** > **App registrations**.
2. Search for your app under 'all applications'.
3. Click **API permissions** > **Add permission**.
4. Search for the specific Microsoft API and select the specific permission of type Delegated.

### Authentication Using the Client Credentials Flow

1. Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

   *Note:* In the *Select members* section, assign the application you created earlier.

2. To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
   b. In the *Application ID* field, enter your Client/Application ID.
   c. In the *Subscription ID* field, enter your Subscription ID.
   d. In the *Resource Group Name* field, enter you Resource Group Name.
   e. In the *Tenant ID* field, enter your Tenant ID .
   f. In the *Client Secret* field, enter your Client Secret.
   g. Click **Test** to validate the URLs, token, and connection
   h. Save the instance.

To connect to the Azure integration, do the following.


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

### Authentication Using the Client Credentials Flow

1. Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

   *Note:* In the *Select members* section, assign the application you created earlier.

2. To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
   a. In the *Application ID* field, enter your Client/Application ID.
   b. In the *Subscription ID* field, enter your Subscription ID.
   c. In the *Resource Group Name* field, enter you Resource Group Name.
   d. In the *Tenant ID* field, enter your Tenant ID .
   e. In the *Client Secret* field, enter your Client Secret.
   f. Click **Test** to validate the URLs, token, and connection
   g. Save the instance.

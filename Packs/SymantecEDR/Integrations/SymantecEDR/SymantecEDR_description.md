## Symantec Endpoint Detection and Response (EDR)
Symantec Endpoint Detection and Response allows you to access incident and event data and perform remediation tasks using APIs and through integration with third-party applications. 
To secure Symantec EDR data, these integrations require you to generate an OAuth2 client. The OAuth client authorizes third-party applications to communicate with Symantec EDR.

### Must have Admin roles to generate an OAuth client. 
Only users with the Admin role who created the OAuth client can view the Client ID and Client Secret. 

### Generate an OAuth client
1. In the EDR appliance console, click **Settings** > **Data Sharing**.
2. In the OAuth Clients section, click **Add Application**.
3. In the App Name field, type the name of the application that you want to register.
4. Select the API version that you intend to use. The default setting is *version 2*. Use version 2 generated OAuth clients. 
5. If you select to enable version 2 APIs, a *Role option* appears. 
6. Click the drop-down menu and select the user role for the app.
   - User: Permits access to all public APIs that have view privileges.
   - Admin: Permits access to all public APIs
7. Click **Generate**. The client ID and client secret appear.

### To view an existing OAuth client ID and client secret
In the OAuth Clients table, hover over the row that contains the information that you want to view. Options appear to the right of the row.

## Celonis Help

#### How to create an OAuth client and generate client ID and Client Secret:

1. To start, you need to create an OAuth client in your team and then grant this client API permissions.
2. Click **Admin & Settings** and select **Applications**.
3. Click **Add New Application - OAuth client** and create your OAuth client.
When creating your OAuth client, use the following configurations: **Authentication method: Client secret post**.
4. Select the following scopes:
   - **audit.log:read (For the Audit Log API)**.
   - **platform-adoption.tracking-events:read** (For the Studio Adoption API).
   - **team.login-history:read** (For the Login History API).
5. Click **Create** and then copy the client ID and client secret to your clipboard for later use.
6. Click **Permissions** and edit Team permissions.
7. Assign **Audit Log API**, ***Login History API**, and **Studio Adoption APIs** permissions to your newly created application as required.
8. Click **Save**.
The OAuth client now has the relevant API permissions. 

[For more information visit Celonis Audit Logs Documentation.](https://developer.celonis.com/celonis-apis/audit-log-api/#creating-an-application-and-granting-it-api-permissions)
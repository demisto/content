## Genesys Cloud Help

### How to obtain OAuth Credentials (Client ID & Secret)

The steps below require a user account with Admin access.

1. Log in to **Genesys Cloud** and click on the **Admin** tab.

2. On the Admin page, click on **OAuth** (under Integrations).

3. On the OAuth page, click **Add client**.

4. In the **App Name** field, enter a descriptive name (e.g., Cortex XSIAM Collector).

5. (Optional) In the **Description** field, enter a description.

6. In the **Grant Types** field, select [**Client Credentials Grant**](https://developer.genesys.cloud/api/rest/authorization/use-client-credentials.html).

7. Click **Next**.

8. In the **Assign Roles** table, enable the toggle for each role required by the XSIAM collector.
    - Ensure the "**Audits** > **Audit** > **View**" permission is selected.
    - Update the associated divisions for the roles as required; otherwise, they default to the **Home** Division.
    - If assigning roles for Genesys Cloud for Salesforce, see also [OAuth client permissions for Genesys Cloud for Salesforce](https://help.mypurecloud.com/articles/oauth-client-permissions-for-genesys-cloud-for-salesforce/).

9. Click **Next**.

10. In the **Token Duration in seconds** field, enter the required duration (the default value of 86400 seconds is generally acceptable).

11. Click **Save**.

12. Store the generated **Client ID** and **Client Secret** in a secure location.

13. Click **Finish** and then **Confirm** to complete the process.

14. Use the **Client ID** and **Client Secret** to configure a new instance of this integration.

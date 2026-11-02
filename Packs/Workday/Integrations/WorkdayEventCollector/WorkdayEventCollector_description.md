## Workday Event Collector

Use this integration to collect activity logs automatically from Workday.

This collector uses OAuth 2.0 (Client ID, Client Secret and Refresh Token). It does not use a Workday username and password.

#### Client ID and Client secret

1. To register the API client, access the **Register API Client for Integrations** task and provide the relevant parameters.
2. Copy the **Client Secret** and **Client ID**.

#### Server URL and Token endpoint

1. Access the **View API Clients** task and copy the below two parameters from the top of the page:
   1. **Workday REST API Endpoint**, for example, `https://wd5-services1.myworkday.com/ccx/api/v1/acme`.
   2. **Token Endpoint**, for example, `https://wd5-services1.myworkday.com/ccx/oauth2/acme/token`.
2. **Server URL**: Use the REST API endpoint with `/api/v1/` replaced by `/api/privacy/v1/`, for example, `https://wd5-services1.myworkday.com/ccx/api/privacy/v1/acme`.
3. **Token endpoint**: Use the Token Endpoint as is.

#### Refresh token

1. Go to the **API Clients for Integrations** tab, hover over the relevant client, and click the three-dot action button.
2. In the new pop-up window, click **API Client** > **Manage Refresh Token for Integrations**.
3. In the **Manage Refresh Token for Integrations** window, select the relevant integration name in the **Workday Account** field and click **OK**.
4. In the newly opened window, select the **Generate New Refresh Token** checkbox and click **OK**.
5. Copy the value of the **Refresh Token** column from the opened window and click **Done**.

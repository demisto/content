## Workday Event Collector

Use this integration to collect activity logs automatically from Workday.

In order to use this integration, you need to enter your Workday credentials in the relevant integration instance parameters.

#### Client ID and Client secret

1. To register the API client, access the Register API Client for Integrations task and provide the relevant parameters.
2. Copy the Client Secret and Client ID

#### Refresh token

1. To generate a refresh token, access the View API Clients task and copy the below two parameters from the top of the page:
   1. Workday REST API Endpoint. The endpoint to use access to the resources in your Tenant.
   2. Token Endpoint. The endpoint used to exchange an authorization code for a token (if you configure authorization code grant).
2. Go to API Clients for Integrations tab hover on the relevant client and click on the three-dot action buttons.
3. In the new pop up window, click API Client > Manage Refresh Token for Integrations.
4. In the Manage Refresh Token for Integrations window, select the relevant integration name in the Workday Account field and click OK.
5. In the newly opened window, select Generate New Refresh Token checkbox and click OK.
6. Copy the value of the Refresh Token column from the opened window and click Done.

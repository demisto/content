### API 2.0 Authentication

To use API 2.0, you need to generate a **Client ID** and **Client Secret** from the Mimecast admin console:

1. Navigate to **Admin** > **Services** > **API and Platform Integrations** > **Available integrations**.
2. Locate the Mimecast API 2.0 tile and select **Generate Keys**.

Make sure you have provided the Client ID and Client Secret, and that the BaseUrl is set to `https://api.services.mimecast.com`.


### API 1.0 Authentication

1. In order to refresh token / discover auth types of the account / create new access & secret keys, 
you are required to provide: App ID, Account email address & password, and BaseUrl is set to `https://<region>-api.mimecast.com`, based on your [region](https://integrations.mimecast.com/documentation/api-overview/global-base-urls/).
These parameters support the following integration commands: 
mimecast-login -> fetches new access key & secret key
mimecast-discover -> lists supported auth types of user
mimecast-refresh-token -> refreshes the validity duration of access key & secret key (3 days)

2. In order to use the rest of the commands, you are required to provide: App ID, App Key, Access Key & Secret Key.
For detailed information about creating these fields, please refer to the [Mimecast Documentation](https://integrations.mimecast.com/documentation/api-overview/authentication-scripts-server-apps/).


### Fetch Incidents

In order to activate them check the **fetch incidents** checkbox, and then check the relevant boxes for each fetch type you want.

- url
- attachment
- impersonation
Mimecast uses quotas per period of time (i.e., rate limits) that apply to every API function, per registered app. A typical quota is a number of API calls per unit of time (but could also be expressed as the size of data returned, etc.). When the quota has been exhausted, further requests will fail until the new time period restarts the count of API calls. The rate limit reset value is the length of time in milliseconds before a minimum of one API will be permitted.

### Rate Limiting

https://developer.services.mimecast.com/api-overview#rate-limiting
Mimecast uses quotas per period of time (i.e. rate limits) that apply to every API function, per registered App. A typical quota is a number of API calls per unit of time (but could also be expressed as the size of data returned, etc.). When the quota has been exhausted, further requests will fail until the new time period restarts the count of API calls. The rate limit reset value is the length of time in milliseconds before a minimum of 1 API will be permitted.

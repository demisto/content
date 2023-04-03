## Zoom Event Collector
Use this integration to collect operation logs and activity reports automatically from Zoom.
You can also use the ***zoom-get-events*** command to manually collect events.

In order to use this integration, you need to enter your Zoom credentials in the relevant integration instance parameters.

Log in to your Zoom admin user account, and follow these steps:
Click [here](https://marketplace.zoom.us/develop/create) to create an app.
### For the OAuth method:
- Enable permissions.
- Create an Server-to-Server OAuth app.
- Add relevant scopes: report:read:admin
- Use the following account credentials to get an access token:
    Account ID
    Client ID
    Client secret

For more information about creating an OAuth app click [here](https://marketplace.zoom.us/docs/guides/build/server-to-server-oauth-app/).

### Rate Limits
To prevent abuse and ensure service stability, all API requests are rate limited. Rate limits specify the maximum number of API calls that can be made in a minute period. The exact number of calls that your application can make per minute varies based on company plan. 
For more information, please refer to the Zoom API documentation on [Rate limits by account type](https://developers.zoom.us/docs/api/rest/rate-limits/#rate-limits-by-account-type).
## Zoom Integration
In order to use this integration, you need to enter your Zoom credentials in the relevant integration instance parameters.
There are two authentication methods available: **OAuth** and **JWT**(deprecated).

Log in to your Zoom admin user account, and follow these steps:
Click [here](https://marketplace.zoom.us/develop/create) to create an app.
### For the OAuth method:
- Enable permissions.
- Create an Server-to-Server OAuth app.
- Add relevant scopes.
- Use the following account credentials to get an access token:
    Account ID
    Client ID
    Client secret

For more information about creating an OAuth app click [here](https://marketplace.zoom.us/docs/guides/build/server-to-server-oauth-app/).

### For the JWT method (deprecated)
- Create an JWT app.
- Use the following account credentials to get an access token:
    API Key
    API Secret

Note: This authentication method will be deprecated by Zoom in June 2023.
For more information about creating an JWT app click [here](https://marketplace.zoom.us/docs/guides/build/jwt-app/).

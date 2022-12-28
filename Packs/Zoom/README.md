## Zoom and Zoom IAM Integrations
In order to use these integrations, you need to enter your Zoom credentials in the relevant integration instance parameters.
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

For more information about creating an OAuth app click [here](https://marketplace.zoom.us/docs/guides/build/jwt-app/).
***

### Troubleshooting - OAuth
Important notes:
- You must have your app activated for the OAuth authentication method.
- Your API token is generated based on the permission you give it, AKA scopes.
- If you initially allow certain permissions, and now you deleted those permissions, your token is still valid with the previous permissions. After 1 hour the old token will expire and a new and limited token will be generated.
- If you want to kill the token permissions immediately, you can deactivate your app.

## Zoom and Zoom IAM Integrations
In order to use these integrations, you need to enter your Zoom credentials in the relevant integration instance parameters.
There are two authentication methods available: **OAuth** and **JWT**(deprecated).
### For the OAuth method:
Please login to your Zoom admin user account, and follow these steps:
- Enable permissions
- Create an Server-to-Server OAuth app
- Add relevant scopes
- Use the following account credentials to get an access token:
    Account ID
    Client ID
    Client secret
for more information about the setup [click here](https://marketplace.zoom.us/docs/guides/build/server-to-server-oauth-app/).


### For the JWT method (deprecated)
To get the credentials, login to your Zoom account, click [here](https://marketplace.zoom.us/develop/create) and choose JWT.
- Use the following account credentials to get an access token:
    API Key
    API Secret
***

### Truble shooting - OAuth
Important nots:
- You must have your app activated for the OAuth authentication method.
- Your API token is generated based on the permission you give it, AKA scopes.
- If you initially allow cretin permissions, and now you deleted those permissions, your token is still valid with the previous permissions, only after 1 our the oldest token will expire and a new and limited token will be generated.
- If you want to kill the tokens permissions  immediately, you can deactivate your app.

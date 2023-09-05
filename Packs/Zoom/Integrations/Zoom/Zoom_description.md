## Zoom Integration
In order to use this integration, you need to enter your Zoom credentials in the relevant integration instance parameters.
authentication methods available: **OAuth** 

**Note: JWT authentication method was deprecated by Zoom from June 2023 and not available anymore**

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

### For Mirroring -

to enable the integration to communicate directly with zoom for mirroring 
This requires a dedicated zoom Team Chat app to be created for the XSOAR integration. For instructions on how to create and configure your custom Slack app, please review the documentation found [here](https://xsoar.pan.dev/docs/reference/integrations/zoom).
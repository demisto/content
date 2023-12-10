Before using Okta v2, you need to perform several configuration steps in your Okta environment.

## Authentication using API Token
Okta API tokens are used to authenticate requests to Okta APIs. 

### Prerequisites
1. Sign in to your Okta organization as a user with administrator privileges.
2. In the Admin Console, select **Security > API** from the menu and then select the **Tokens** tab.
3. Click **Create Token**.
4. Name your token and click **Create Token**.

#### Notes
- API tokens have the same permissions as the user who creates them, and if the user permissions change, the API token permissions also change.

For more information, see the '[Create an API token
](https://developer.okta.com/docs/guides/create-an-api-token/main/)' official documentation article.

## Authentication using OAuth 2.0 Authentication
As an alternative to Okta API tokens, you can interact with Okta APIs using scoped OAuth 2.0 access tokens for a number of Okta endpoints.  
Each access token enables the bearer to perform specific actions on specific Okta endpoints, with that ability controlled by which scopes the access token contains.

### Required Scopes
The following scopes are required for the Okta v2 integration to work properly:
- okta.apps.manage 
- okta.apps.read 
- okta.groups.manage 
- okta.groups.read 
- okta.logs.read 
- okta.networkZones.manage 
- okta.networkZones.read 
- okta.sessions.manage 
- okta.sessions.read 
- okta.users.manage 
- okta.users.read 


### Prerequisites
1. Generate an API token as described previously. This is required for some backend API calls that are needed to setup OAuth authentication.
2. Sign in to your Okta organization as a user with administrative privileges.
3. In the Admin Console, go to **Applications > Applications**.
4. Click **Create App Integration**.
5. Select **API Services** as the sign-in method, and click **Next**.
6. Enter a name for your app integration.
7. On the app configuration page, under the **General** tab and the **Client Credentials** section, select **Public key / Private key** for the **Client authentication** option.
8. Under the newly added **PUBLIC KEYS** section, click the **Add Key** button.
9. In the **Add Public Key** dialog, click **Generate new key**, and make sure to keep the private key (in PEM format) in somewhere safe.
10. On the app configuration page, under the **Okta API Scopes** tab, make sure that the required scopes mentioned above are granted.

For more information, see the '[Implement OAuth for Okta
](https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/)' official documentation article.

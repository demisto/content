## Authentication using API Token
Okta API tokens are used to authenticate requests to Okta APIs. 

### Prerequisites
1. Sign in to your Okta organization as a user **with administrator privileges**.
2. In the Admin Console, select **Security** > **API** from the menu, and then select the **Tokens** tab.
3. Click **Create Token**.
4. Name your token and click **Create Token**.

#### Notes
- API tokens have the same permissions as the user who creates them, and if the permissions of a user change, so do the permissions of the API token.

For more information, see the '[Create an API token](https://developer.okta.com/docs/guides/create-an-api-token/main/)' official documentation article.

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
1. Sign in to Okta Admin Console.
2. In the Admin Console, go to **Applications** > **Applications**.
3. Click **Create App Integration**.
4. Select **API Services** as the sign-in method, and click **Next**.
5. Enter the desired name for the created app (e.g., "Cortex XSOAR"), and click **Save**.
6. In the app configuration page, under the **General** tab and the **Client Credentials** section, select **Public key / Private key** for the **Client authentication** option.
7. Under the newly added **PUBLIC KEYS** section, click **Add Key**.
8. In the **Add Public Key** dialog box, click **Generate new key**. Make sure to copy the generated private key (in PEM format) to somewhere safe, and click **Save**.
9. Under the **General Settings** section:
   1. Next to the **Proof of possession** label, uncheck the **Require Demonstrating Proof of Possession (DPoP) header in token requests** option if it's selected.
   2. Next to the **Grant type** label, make sure the **Client Credentials** option is selected, and that the **Token Exchange** option is not selected.
   3. Click **Save**.
10. Under the **Okta API Scopes** tab, grant the required scopes mentioned above for the app.
11. Under the **Admin roles** tab:
    1. Click **Edit assignments**.
    2. In the dropdown list under "Role", select **Super Administrator**.
    3. Click **Save changes** at the top.

For more information, see the '[Implement OAuth for Okta](https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/)' official documentation article.
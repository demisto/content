## Cloudflare Zero Trust

Use this integration to fetch account audit logs, user audit logs, and access authentication logs from Cloudflare Zero Trust as events in Cortex XSIAM.

Two authorization types are supported:

- **API Token** - Requires generating an account or a user API token.
- **Global API Key (Legacy)** - Requires retrieving the global API key and finding the associated Email address.

---

### **API Token (Recommended)**

Two API token types are supported:

- **Account token** - Allows you to set up durable integrations that can act as service principals with their own specific set of permissions.
- **User token** - Acts on behalf of a particular user and inherits a subset of that user's permissions.

User tokens are better for ad hoc tasks like scripting, where acting as the user is ideal and durability is less of a concern.

It is recommended to use an **account token** to set up this integration.

#### Generate API Token

1. Go to the [Cloudflare dashboard](https://dash.cloudflare.com).
   - For account tokens (recommended), navigate to **Manage Account** > **API Tokens**.
   - For user tokens, navigate to **My Profile** > **API Tokens**
2. Click **Create Token**.
3. Scroll to the **Custom token** section and click **Get started**.
4. Give the token a descriptive name.
5. Set the token's permissions, as follows:
    - **Account** - **Account Settings** - **Read**
    - **Account** - **Access: Audit Logs** - **Read**
6. For user tokens, choose which account resources the token is authorized to access, as follows:
    - **Include** - **All accounts**
7. [Optional] Restrict how the token is used in the Client IP Address Filtering and TTL (time to live) fields.
8. Click **Continue to summary** at the bottom of the screen.
9. Click **Create Token** to generate a new API access token.
10. Store the token in a secure location and use it to configure a new instance of this integration.

To learn more about API tokens, visit the [Cloudflare API Tokens Documentation](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)

---

### **Global API Key (Legacy)**

Global API key is the previous authorization scheme for interacting with the Cloudflare API. When possible, use API tokens instead of Global API keys.

#### Retrieve Global API Key

1. Go to the [Cloudflare API Tokens page](https://dash.cloudflare.com/profile/api-tokens).
2. Scroll to the **API Keys** section.
3. Click **View** to reveal the Global API Key.  (You may need to enter your password).
4. Store the global key in a secure location and use it to configure a new instance of this integration.

To learn more about the Global API Key, visit the [Cloudflare API Key Documentation.](https://developers.cloudflare.com/fundamentals/api/get-started/keys/).

#### Find Associated Email

The associated API email can be found on the [Cloudflare My Profile page](https://dash.cloudflare.com/profile).

For more details on verifying your associated email, refer to [Verify Cloudflare Email Address](https://developers.cloudflare.com/fundamentals/setup/account/verify-email-address/).

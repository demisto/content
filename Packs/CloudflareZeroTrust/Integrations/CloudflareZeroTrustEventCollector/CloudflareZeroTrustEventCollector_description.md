## Cloudflare Zero Trust

Use this integration to fetch account audit logs, user audit logs, and access authentication logs from Cloudflare Zero Trust as events in Cortex XSIAM.

#### **Retrieve Global API Key**


1. Go to [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens).
2. Scroll to the **API Keys** section.
3. Click **View** to reveal the Global API Key.  (You may need to enter your password).
To learn more about the Global API Key, visit the [Cloudflare API Key Documentation.](https://developers.cloudflare.com/fundamentals/api/get-started/keys/).

#### **Find Associated Email**

The associated API email can be found here: [Cloudflare Profile](https://dash.cloudflare.com/profile).

For more details on verifying your associated email, visit the  [Verify Email Address](https://developers.cloudflare.com/fundamentals/setup/account/verify-email-address/).


#### **Token Permissions**

This API token will affect the following accounts and zones, along with their respective permissions:

- All accounts:

  - Account Analytics: Read
  - Access Audit Logs: Read
- All zones:

  - Logs: Read
  - Analytics: Read
## Cloudflare Zero Trust

_____
Use this integration to fetch account audit logs, user audit logs, and access authentication logs from Cloudflare Zero Trust as events in Cortex XSIAM.
_____

#### **2. Retrieve Global API Key**

- Visit [Retrieve Global API Key](https://developers.cloudflare.com/fundamentals/api/get-started/keys/).

  **Note:** The Global API Key is an all-purpose token that can read and edit any data or settings that you can access in the dashboard.  
  - API Key is available here: [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)  

#### **3. Find Associated Email**

- Visit [Verify Email Address](https://developers.cloudflare.com/fundamentals/setup/account/verify-email-address/).
- **API email** can be found here: [Cloudflare Profile](https://dash.cloudflare.com/profile).  

### Notes:

The global rate limit for the Cloudflare API is 1200 requests per five minutes per user, and applies cumulatively regardless of whether the request is made via the dashboard, API key, or API token.
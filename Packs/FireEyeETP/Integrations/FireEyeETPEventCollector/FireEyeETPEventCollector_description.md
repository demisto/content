Trellix Email Security - Cloud enables you to fetch events of type Alert, Email Trace, and Activity Log from your system.

# Authentication Configuration

To ensure a successful connection, you must select the correct authentication method based on the Base URL (Instance URL) you are configuring.

### Cloud service regions

Use the URLs for the region that hosts your Email Security — Cloud service:

* US Instance: `https://etp.us.fireeye.com/` or `https://us.etp.trellix.com`

* EMEA Instance: `https://etp.eu.fireeye.com/` or `https://eu.etp.trellix.com`

* APJ Instance: `https://etp.ap.fireeye.com/` or `https://ap.etp.trellix.com`

* USGOV Instance: `https://etp.us.fireeyegov.com/`

* CA Instance: `https://etp.ca.fireeye.com/` or `https://ca.etp.trellix.com`

We support two different authentication methods depending on the endpoint domain:

| **Domain Used in Server URL** | **Authentication Method** | **Required Parameters** | 
| :--- | :--- | :--- | 
| **Ends in `trellix.com`** | **OAuth 2.0** | **Client ID**, **Client Secret**, and **OAuth Scopes** | 
| **Ends in `fireeye.com`** | **API Key** | **API Key** (only) | 

For official documentation on configuring access, [see here.](https://docs.trellix.com/bundle/etp_api/page/UUID-30726aa3-e420-6f62-6b84-6ad0bdace483.html)

# Configuring API keys

Follow these steps to configure API keys:

1. Log in to the Email Security — Cloud Web Portal or IAM console.

2. Click **My Settings** in the top navigation bar.

3. Click the **API Keys** tab in the IAM console.

4. Click **Create API Key**.

5. On the Manage API Key page, specify the following:

   * API key name.

   * Expiration time for the API key. The expiration time of API keys should be set as “100d” for 100 days, or “1y” for 1 year, for example.

   * Products. Select both “Email Threat Prevention” and “Identity Access Management”.

6. Select all entitlements as shown below.

7. To download or copy an API key, click the download or copy icon in the bottom right corner.

8. Click **Create API Key**.

### Permissions

For any API access, the following entitlements are required:

* iam.users.browse

* iam.orgs.self.read

* etp.alerts.read (For accessing alerts APIs)

* etp.email_trace.read (For accessing trace APIs)



# Configuring OAuth 2.0 Credentials (Trellix Endpoints)

Use this method for **trellix.com** domains.

1. Generate the Client ID and Client Secret following the official Trellix documentation.

2. Copy the list of authorized OAuth Scopes provided during creation.

3. When creating the Client ID and Client Secret, ensure the corresponding user/role has **explicit permission to access the API**.

   * **Note:** If API access permissions are not properly set for the user/role, the authentication attempt will fail with a **`400 Client Error: Bad Request`**, even if the Client ID and Secret are otherwise correct.
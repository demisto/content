FireEye Email Threat Prevention Event Collector allows you to fetch events of type Alert, Email Trace ad Activity Log from your system.

# Configuring API keys
Follow these steps to configure API keys:
1. Log in to the Email Security — Cloud Web Portal or IAM console.
2. Click **My Settings** in the top navigation bar.
3. Click the **API Keys** tab in the IAM console.
4. Click **Create API Key**.
5. On the Manage API Key page, specify the following:
   - API key name.
   - Expiration time for the API key. The expiration time of API keys should be set as “100d” for 100 days, or “1y” for 1 year, for example.
   - Products. Select both “Email Threat Prevention” and “Identity Access Management”.
6. Select all entitlements as shown below.
7. To download or copy an API key, click the download or copy icon in the bottom right corner.
8. Click **Create API Key**.
   
# Permissions
For any API access, the following entitlements are required:
- iam.users.browse
- iam.orgs.self.read
- etp.alerts.read (For accessing alerts APIs)
- etp.email_trace.read (For accessing trace APIs)

## Cloud service regions
Use the URLs for the region that hosts your Email Security — Cloud service:

- US Instance: https://etp.us.fireeye.com/
- EMEA Instance: https://etp.eu.fireeye.com
- APJ Instance: https://etp.ap.fireeye.com/
- USGOV Instance: https://etp.us.fireeyegov.com/
- CA Instance: https://etp.ca.fireeye.com/

For more information, see the [Official Product Documentation](https://docs.trellix.com/bundle/etp_api/page/UUID-98fd1a2c-382d-130b-00c5-b9be402fe660_1.html#idm44910884288000).
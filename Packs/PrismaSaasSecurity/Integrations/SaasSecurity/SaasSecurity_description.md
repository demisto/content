Creating the Client ID and Client Secret
---
In the Saas Security UI:
- Setting -> SettingsExternal.
- Click ***Add API Client***.
- Enter a unique Name for the API client.
- Authorize the API client for the [required scopes](#required-scopes).
- Copy the ***Client ID*** and ***Client Secret***.

***Tip***: Record your API client secret somewhere safe. For security purposes, it's only shown when you create or reset the API client. If you lose your secret, you must reset it, which removes access for any integrations that still use the previous secret.

For more information see [Prisma Saas Security Documentation](https://docs.paloaltonetworks.com/saas-security/saas-security-admin/saas-security-api/syslog-and-api-integration/api-client-integration/add-your-api-client-app.html#idd6102853-02a3-48b2-b5ca-7aeca3822a4f) 

 Required Scopes
---
- Log access — Access log files.
- Incident management — Retrieve and change incident status.
- Quarantine management — Quarantine assets and restore quarantined assets.


Sever URLs
---
Choose the instance configuration base URL based on the server location:
- https://api.aperture.paloaltonetworks.com (US)
- https://api.aperture-eu.paloaltonetworks.com (EU)
- https://api.aperture-apac.paloaltonetworks.com (APAC)
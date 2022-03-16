Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
Creating the Client ID and Client Secret
---
In the SaaS Security UI:
1. Navigate to **Settings** > **External Service**.
2. Click **Add API Client**.
3. Enter a unique name for the API client.
4. Authorize the API client for the [required scopes](#required-scopes). You use these scopes in the POST request to the /oauth/token endpoint.
5. Copy the ***Client ID*** and ***Client Secret***.

***Tip***: Record your API client secret somewhere safe. For security purposes, it's only shown when you create or reset the API client. If you lose your secret, you must reset it, which removes access for any integrations that still use the previous secret.

For more information see [Saas Security Documentation](https://docs.paloaltonetworks.com/saas-security/saas-security-admin/saas-security-api/syslog-and-api-integration/api-client-integration/add-your-api-client-app.html#idd6102853-02a3-48b2-b5ca-7aeca3822a4f) 

 Required Scopes
---
- Log access — Access log files. You can either provide this API client log access or add a syslog receiver for this purpose.
- Incident management — Retrieve and change the incident status.
- Quarantine management — Quarantine assets and restore quarantined assets.


Sever URLs
---
Choose the instance configuration base URL based on the server location:
- https://api.aperture.paloaltonetworks.com (US)
- https://api.aperture-eu.paloaltonetworks.com (EU)
- https://api.aperture-apac.paloaltonetworks.com (APAC)


Note: SaaS Security API currently allows you to mirror out only closed incidents, and only their **state** and **category** fields.
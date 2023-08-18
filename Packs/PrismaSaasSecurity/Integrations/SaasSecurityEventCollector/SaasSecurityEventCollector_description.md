
## Limitations
1) Occurring events expire after one hour in Saas-Security cache, so setting a low limit could cause events to expire if there are a large number of events in the Saas-Security cache.
2) If the ```max_fetch``` is not dividable by 10, it will be rounded down to a number that is dividable by 10 due to SaaS Security api limits.
3) **reset last fetch** has no effect.
4) On initial activation this integration will pull events starting from one hour prior.
5) Using the ```saas-security-get-events``` command may take upwards of twenty seconds in some cases.
6) In some rare cases more than ```max_fetch``` events could be fetched.
7) The maximum recommended max fetch is 5000 to avoid fetch timeouts.
8) In case not providing the ```max_fetch``` argument, the default will be 1000.


Creating the Client ID and Client Secret in the SaaS Security UI:
---

1. Navigate to **Settings** > **External Service**.
2. Click **Add API Client**.
3. Specify a unique name for the API client.
4. Authorize the API client for the required scopes. You use these scopes in the POST request to the /oauth/token endpoint. The Required Scopes are:
- Log access — Access log files. You can either provide the client log access API or add a syslog receiver.
- Incident management — Retrieve and change the incident status.
- Quarantine management — Quarantine assets and restore quarantined assets.
5. Copy the ***Client ID*** and ***Client Secret***.

***Tip***: Record your API client secret somewhere safe. For security purposes, it's only shown when you create or reset the API client. If you lose your secret, you must reset it, which removes access for any integrations that still use the previous secret.
6. Add the **Client ID** and **Client Secret** to Cortex XSOAR.
Note: For more information see the [SaaS Security Administrator's Guide](https://docs.paloaltonetworks.com/saas-security/saas-security-admin/saas-security-api/syslog-and-api-integration/api-client-integration/add-your-api-client-app)

Sever URLs
---
Choose the instance configuration base URL based on the server location:
- https://api.aperture.paloaltonetworks.com (US)
- https://api.aperture-eu.paloaltonetworks.com (EU)
- https://api.aperture-apac.paloaltonetworks.com (APAC)
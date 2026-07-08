## CyberArk EPM Help

### Authentication

This integration uses OAuth2 authentication via CyberArk Identity. You will need to configure the following parameters:

- **EPM Tenant URL**: The region-based EPM API URL (e.g., `https://api-na.epm.cyberark.cloud`).
- **Identity URL**: The CyberArk Identity FQDN for OAuth2 (e.g., `https://<TENANT_ID>.id.cyberark.cloud`).
- **Web App ID**: The Application ID of the OAuth2 Server web app configured in CyberArk Identity.
- **Client ID**: The service username (OAuth confidential client).
- **Client Secret**: The service user password.
- **Set name**: A comma-separated list of EPM set names to collect events from.

### Fetch Information

- There are three event types that are fetched for the Event Collector:
    * Policy audits.
    * Admin audits.
    * Events.

* The `set name` parameter contains a list of names to which the events are related.
* The `max fetch` parameter is for every event type and for every name in the `set name` parameter which means that for `max fetch` that equals 1000 the actually max events fetched will be 3000 * sum of names in the `set name` parameter.

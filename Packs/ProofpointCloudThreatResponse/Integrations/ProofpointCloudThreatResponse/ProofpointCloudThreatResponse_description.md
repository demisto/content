## Proofpoint Cloud Threat Response Help

Use this integration to fetch incidents from Proofpoint Cloud Threat Response (CTR) into Cortex XSOAR and to retrieve incident details on-demand.

### Prerequisites

Before configuring the integration, verify you have the following:

- **Proofpoint API credentials**: A valid **Client ID** and **Client Secret** generated from your Proofpoint Threat Response account. These credentials are used to obtain a Bearer token from `https://auth.proofpoint.com/v1/token` using the OAuth2 `client_credentials` grant.
- **API root URL**: The endpoint for your Proofpoint Cloud Threat Response instance. The default is `https://threatprotection-api.proofpoint.com`.

For details on generating API credentials, see [API Key Management](https://help.proofpoint.com/Admin_Portal/Settings/API_Key_Management).

### Fetch incidents

When **Fetch incidents** is enabled, the integration polls `POST /api/v1/tric/incidents` using a sliding time window built from the configured **First fetch timestamp** and the **Fetch delta (minutes)**. For each returned incident a follow-up call to `GET /api/v1/tric/incidents/<id>` is performed to enrich the raw JSON with activities and summary information before the incident is created in Cortex XSOAR.

You must set **Fetch incident with specific states** to either `open_incidents` **or** `closed_incidents` when fetch is enabled. Passing both values is rejected by the upstream API and returns an empty result.

### Known limitations

- The Cloud Threat Response API does not currently expose endpoints for closing incidents, managing block lists (domains/IPs/URLs/hashes), ingesting alerts, or quarantine verification. As a result, those commands are not part of this integration. Closure of incidents must be performed in the CTR UI.
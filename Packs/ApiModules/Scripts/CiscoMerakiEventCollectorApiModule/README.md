Common code for the Cisco Meraki Event Collector integrations.

Holds the collector implementation (`run_cisco_meraki_event_collector`), shared by the **Cisco Meraki Event Collector** integration (cisco-meraki pack) and its standard-connector duplicate (CiscoMerakiStandardConnector pack). Authentication (UCP / OAuth 2.0 / API key) and rate-limit handling come from `CiscoMerakiApiModule`.

Collected event types, each with its own fetch budget and state:

| Event type | Endpoint |
| --- | --- |
| Configuration changes | `GET /organizations/{organizationId}/configurationChanges` |
| Network events | `GET /networks/{networkId}/events` (per network and product type) |
| API requests | `GET /organizations/{organizationId}/apiRequests` |
| Appliance security events | `GET /organizations/{organizationId}/appliance/security/events` |

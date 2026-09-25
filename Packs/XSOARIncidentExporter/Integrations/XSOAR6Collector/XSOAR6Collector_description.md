## XSOAR 6 Incident Collector

This integration runs on Cortex XSIAM and fetches incidents from a remote Cortex XSOAR 6 instance.

### Prerequisites

- **XSOAR 6 API Key**: Generate an API key on the XSOAR 6 instance under **Settings > Integrations > API Keys**. The key must have permissions to read incidents.
- **Network Connectivity**: The XSIAM environment must be able to reach the XSOAR 6 server over HTTPS. If the XSOAR 6 instance is on-premises behind a firewall, you may need to configure a **Broker VM** to proxy the connection.

### Features

- **Fetch Incidents**: Automatically collects incidents from XSOAR 6 on a periodic schedule. Incidents are created in XSIAM with the original XSOAR 6 metadata preserved in custom fields.
- **Manual Search**: Use the `xsoar6-get-incidents` command to query incidents on-demand with optional filters.
- **Single Incident Lookup**: Use the `xsoar6-get-incident` command to retrieve full details for a specific incident by ID.

### Configuration Notes

- **Trust any certificate** is disabled by default. Enable it if the XSOAR 6 server uses a self-signed certificate.
- **Incident query filter** accepts the same query syntax used in the XSOAR 6 incidents search bar (e.g., `type:Phishing`, `severity:high`, `status:active`).
- **First fetch time** controls how far back the initial fetch looks for incidents. Subsequent fetches only retrieve incidents created after the last successful fetch.

### Custom Fields

Fetched incidents include the following custom fields for traceability:

| Custom Field | Description |
|---|---|
| `xsoar6incidentid` | Original incident ID on XSOAR 6 |
| `xsoar6owner` | Incident owner on XSOAR 6 |
| `xsoar6status` | Incident status on XSOAR 6 |
| `xsoar6type` | Incident type on XSOAR 6 |
| `xsoar6closedate` | Close date (if closed) |
| `xsoar6closereason` | Close reason (if closed) |

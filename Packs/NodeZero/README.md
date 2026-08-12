# NodeZero

NodeZero is an autonomous penetration testing platform that continuously identifies exploitable weaknesses across your infrastructure. By simulating real-world attack paths, NodeZero provides proof-based findings that help security teams prioritize remediation efforts.

This pack integrates NodeZero with Cortex XSOAR to automatically ingest discovered weaknesses as incidents for tracking, triage, and remediation workflows.

## What Does This Pack Do?

- Fetches HIGH and CRITICAL severity weaknesses from NodeZero pentest operations
- Creates incidents with full weakness context including severity scores, attack paths, and proof status
- Tracks CISA KEV (Known Exploited Vulnerabilities) and ransomware campaign associations
- Enables automated remediation workflows based on weakness severity and exploitability

## Configure NodeZero in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The NodeZero API server URL. | True |
| API Key | The API Key required to authenticate to the NodeZero service. | True |
| Trust any certificate (not secure) | When selected, certificates are not checked. | False |
| Use system proxy settings | Runs the integration instance using the proxy server defined in the server configuration. | False |
| Fetch incidents | When selected, the integration fetches incidents. | False |
| Incident type | The incident type to create for fetched incidents. | False |
| Maximum number of weaknesses to fetch | Maximum number of incidents to fetch per run. | False |
| First fetch time | How far back to fetch on first run (e.g., "7 days", "3 days"). | False |
| Incidents Fetch Interval | How often to fetch new incidents (in minutes). Default is 10080 (7 days). | False |

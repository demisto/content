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
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Maximum number of weaknesses to fetch | Maximum number of incidents to fetch per run. | False |
| First fetch time | How far back to fetch on first run \(e.g., "7 days", "3 days"\). | False |
| Incidents Fetch Interval |  | False |

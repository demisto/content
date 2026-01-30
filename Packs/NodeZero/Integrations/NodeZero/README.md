# NodeZero

Integrates with the NodeZero autonomous penetration testing platform to fetch weaknesses discovered during pentest operations. Automatically ingests HIGH and CRITICAL severity weaknesses as incidents for tracking and remediation.

## Configure NodeZero on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for NodeZero.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The NodeZero API server URL. | True |
| API Key | The API Key required to authenticate to the NodeZero service. | True |
| Trust any certificate (not secure) | When selected, certificates are not checked. | False |
| Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | False |
| Fetch incidents | When selected, the integration fetches incidents. | False |
| Incident type | The incident type to create for fetched incidents. | False |
| Maximum number of weaknesses to fetch | Maximum number of incidents to fetch per run. Default is 200. | False |
| First fetch time | How far back to fetch on first run (e.g., "7 days", "3 days"). Default is 7 days. | False |
| Incidents Fetch Interval | How often to fetch new incidents (in minutes). Default is 10080 (7 days). | False |

4. Click **Test** to validate the URLs, token, and connection.

## Fetch Incidents

The integration fetches HIGH and CRITICAL severity weaknesses from NodeZero pentest operations as incidents. Each weakness is converted to an XSOAR incident with the following mappings:

| **NodeZero Field** | **XSOAR Incident Field** |
| --- | --- |
| uuid | dbotMirrorId |
| created_at | occurred |
| severity | severity (CRITICAL=4, HIGH=3) |
| vuln_id | externalid |
| affected_asset_display_name | sourcehostname |
| ip | sourceip |
| score | nodezeroweaknessscore |
| vuln_category | nodezeroweaknesscategory |
| has_proof | nodezeroweaknessproven |
| attack_paths_count | nodezeroattackpathscount |
| vuln_cisa_kev | nodezerocisakov |
| vuln_known_ransomware_campaign_use | nodezeroransomwareuse |
| op_id | nodezeroopid |

## Commands

This integration does not have user-callable commands. It only supports incident fetching.

## Deduplication

The integration uses ID-based deduplication to prevent duplicate incidents:

- On first run, weaknesses from the last N days (configured via "First fetch time") are fetched.
- On subsequent runs, the integration queries weaknesses since the most recent `created_at` timestamp from the previous fetch.
- UUIDs of weaknesses at the latest timestamp are tracked to avoid re-fetching them if they appear in the next query window.

This ensures that even if multiple weaknesses share the same timestamp, they are only ingested once.

## Known Limitations

- Only HIGH and CRITICAL severity weaknesses are fetched.
- The integration uses a GraphQL API with JWT-based authentication.
- JWT tokens are cached and automatically refreshed before expiration.

## Troubleshooting

If you encounter authentication errors, verify that:

1. The API Key is correct and has not expired.
2. The Server URL is accessible from the XSOAR server.
3. SSL certificates are valid (or "Trust any certificate" is enabled for testing).

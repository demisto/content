# NodeZero

Integrates with the [NodeZero](https://www.horizon3.ai/nodezero/) autonomous penetration testing platform to fetch weaknesses discovered during pentest operations. Automatically ingests HIGH and CRITICAL severity weaknesses as incidents for tracking and remediation.

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

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message is displayed in the War Room with the command details.

### nodezero-get-weaknesses

Retrieves HIGH and CRITICAL weaknesses discovered by NodeZero pentests.

#### Base Command

`nodezero-get-weaknesses`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since_date | Fetch weaknesses created on or after this date (ISO 8601, e.g. 2024-01-01T00:00:00). Defaults to 7 days ago. | Optional |
| limit | Maximum number of weaknesses to return (1–1000). Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NodeZero.Weakness.uuid | String | Unique identifier of the weakness. |
| NodeZero.Weakness.created_at | Date | Timestamp when the weakness was first discovered. |
| NodeZero.Weakness.vuln_id | String | Vulnerability identifier (e.g. CVE ID). |
| NodeZero.Weakness.vuln_name | String | Full vulnerability name. |
| NodeZero.Weakness.vuln_short_name | String | Short vulnerability name. |
| NodeZero.Weakness.vuln_category | String | Vulnerability category. |
| NodeZero.Weakness.vuln_cisa_kev | Boolean | Whether the vulnerability is in the CISA Known Exploited Vulnerabilities catalog. |
| NodeZero.Weakness.vuln_known_ransomware_campaign_use | Boolean | Whether the vulnerability is known to be used in ransomware campaigns. |
| NodeZero.Weakness.ip | String | IP address of the affected asset. |
| NodeZero.Weakness.has_proof | Boolean | Whether NodeZero has proof of exploitability. |
| NodeZero.Weakness.score | Number | Weakness severity score. |
| NodeZero.Weakness.severity | String | Weakness severity level (HIGH or CRITICAL). |
| NodeZero.Weakness.affected_asset_uuid | String | UUID of the affected asset. |
| NodeZero.Weakness.affected_asset_display_name | String | Display name of the affected asset. |
| NodeZero.Weakness.attack_paths_count | Number | Number of attack paths through this weakness. |
| NodeZero.Weakness.op_id | String | ID of the pentest operation that discovered this weakness. |

#### Command example

```!nodezero-get-weaknesses limit=5```

#### Human Readable Output

>### NodeZero Weaknesses
>|uuid|severity|vuln_name|ip|score|has_proof|
>|---|---|---|---|---|---|
>| abc-123 | CRITICAL | Example Vuln | 10.0.0.1 | 9.8 | true |

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

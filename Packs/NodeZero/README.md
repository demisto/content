# NodeZero

NodeZero is an autonomous penetration testing platform that continuously identifies exploitable weaknesses across your infrastructure. By simulating real-world attack paths, NodeZero provides proof-based findings that help security teams prioritize remediation efforts.

This pack integrates NodeZero with Cortex XSOAR to automatically ingest discovered weaknesses as incidents for tracking, triage, and remediation workflows.

<~XSIAM>
In Cortex XSIAM, the pack also includes the **NodeZero Event Collector** integration, which collects every weakness from completed pentests as events, and the **Horizon3 NodeZero Modeling Rule**, which maps those events to the Cortex Data Model (XDM).
</~XSIAM>

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

<~XSIAM>

## NodeZero Event Collector

The **NodeZero Event Collector** integration collects every weakness from completed NodeZero pentests, at all severities, into the `horizon3_nodezero_raw` dataset. Each weakness becomes one event, timestamped at the time NodeZero discovered it during the pentest. The **Horizon3 NodeZero Modeling Rule** maps the events to the Cortex Data Model (XDM).

The event collector runs independently of the **NodeZero** integration, so you can use either one or both.

### What does the event collector do?

- Collects weaknesses only from completed (done) pentests whose results are fully available. A pentest that is stopped before it completes is not collected.
- Collects every severity. Weaknesses without a CVE keep their NodeZero identifier.
- Validates host names before it writes them to the target host fields, and sends IP addresses to the address fields.
- Maps each weakness to the XDM alert fields, including its severity and MITRE ATT&CK tactics and techniques, maps the affected host to the XDM target host fields, and identifies Horizon3 NodeZero as the XDM observer.

### Configure NodeZero Event Collector in Cortex XSIAM

1. In the [Horizon3.ai Portal](https://portal.horizon3ai.com/), navigate to **Settings** > **My Settings** > **API Keys**, click **Generate API Key**, and copy the key value. The key must have **read** access to pentests and weaknesses.
2. In Cortex XSIAM, navigate to **Settings** > **Data Sources** and click **Add Data Source**.
3. Search for **NodeZero** and click **Connect**.
4. Paste the key into the **API Key** parameter, select **Fetch events**, and set the other parameters as needed.
5. Click **Test** to verify that Cortex XSIAM can reach the server and authenticate with the API key, and then save the instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The NodeZero API server URL. Default is `https://api.horizon3ai.com`. | True |
| API Key | A NodeZero API key with read access to pentests and weaknesses. | True |
| Trust any certificate (not secure) | When selected, certificates are not checked. | False |
| Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | False |
| Fetch events | When selected, the integration fetches events. | False |
| Events Fetch Interval | How often, in minutes, to check NodeZero for pentests that have finished. Default is 30. | False |
| First fetch time | On the first fetch only, how far back to collect pentests that have finished (for example, 7 days or 12 hours). Default is 7 days. | False |
| Maximum number of events per fetch | When a fetch reaches this number of events, it doesn't start another pentest, and the next fetch continues with the remaining pentests. A pentest is never split because of this limit. Default is 10000. | False |

### Supported datasets

| **Event type** | **Dataset** |
| --- | --- |
| Weakness | `horizon3_nodezero_raw` |

### Dashboard

The **NodeZero Overview** dashboard shows the NodeZero events from the last 30 days:

- **Ingestion health**: events ingested per day, the number of pentests ingested, hours since the last event was ingested, and a per-pentest table that compares the events ingested with the number of weaknesses NodeZero reported.
- **Weaknesses by severity**: a breakdown by severity, and weaknesses found per day by severity.
- **Top weaknesses and hosts**: the 25 most common weaknesses and the 25 hosts with the most weaknesses.

### Sample XQL queries

Each event's time is when NodeZero discovered the weakness during the pentest, so set a time frame that covers your recent pentests.

The following query returns raw weakness events:

```
config timeframe = 7D
| dataset = horizon3_nodezero_raw
| fields _time, op_id, vuln_id, vuln_name, severity, target_hostname
```

The following query returns the modeled XDM fields:

```
config timeframe = 7D
| datamodel dataset = horizon3_nodezero_raw
| fields xdm.alert.name, xdm.alert.severity, xdm.alert.original_threat_id, xdm.alert.mitre_tactics, xdm.target.host.hostname, xdm.target.host.ipv4_addresses
```

</~XSIAM>

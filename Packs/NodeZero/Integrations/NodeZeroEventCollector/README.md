Collects weakness events from completed NodeZero autonomous pentests into Cortex XSIAM.
Each weakness becomes one event, timestamped (`_time`) at the time NodeZero discovered it during the pentest.

## Collected data

- The integration collects weaknesses only from completed (done) pentests whose results are fully available. A pentest that is still running is collected on the first fetch after it completes. A pentest that is stopped before it completes is not collected.
- Every severity is collected. Weaknesses without a CVE keep their NodeZero identifier in `vuln_id`.
- Each weakness that a pentest finds becomes one event. When two pentests find the same weakness, each pentest produces its own event.
- Host names are validated before they are written to the target host fields. IP addresses go to the address fields, and values that are not valid host names (for example, version strings) are left out.
- Events never include credential secrets or proof contents, such as command output or screenshots.
- Query the events with `dataset = horizon3_nodezero_raw`.

### Data modeling

The **Horizon3 NodeZero Modeling Rule** in this pack maps the events to the Cortex Data Model (XDM):

- The weakness maps to the XDM alert fields, including its name, description, severity, vulnerability ID, MITRE ATT&CK tactics and techniques, and a link to the weakness in the NodeZero portal.
- The affected host maps to the XDM target host fields: host name, FQDN, IPv4 and IPv6 addresses, MAC address, and operating system. Fields that NodeZero has no value for are left empty.
- The XDM observer fields identify Horizon3 NodeZero as the source of the events.

To query the modeled fields, use `datamodel dataset = horizon3_nodezero_raw`.

### Duplicate events

- The scheduled fetch and the **nodezero-fetch-events** command keep one shared record of the pentests they sent. Neither sends a pentest that either one already sent in full, and they never send at the same time: a fetch that starts while the command is sending skips its run, and the command returns an error while a fetch is sending.
- Each event has an `event_id` field that combines the pentest ID and the weakness ID. If a run is interrupted, the next run can send some of the same events again. To remove the duplicates from query results, add `| dedup event_id` to the query.
- The record is kept per integration instance. **Reset the "last run" timestamp** doesn't make the integration send pentests again. To collect pentests again, configure a new instance.

### Requests to NodeZero

Every request the integration sends to NodeZero has a `User-Agent` header in the form `NodeZero-Cortex/<pack version> (NodeZeroEventCollector; Cortex <platform version>)` and an `X-Request-ID` header in the form `<run ID>-<n>`, where the run ID is new for each run and `n` counts the run's requests from 1. A request that is retried after a connection error, a read timeout, or an HTTP 429, 500, 502, 503 or 504 response keeps its request ID. A request that is sent again with a new token after an HTTP 401 gets a new request ID. Scheduled fetches, and runs of **nodezero-fetch-events** that send events, log their run ID in their summary line. When NodeZero answers a request with an error, the error message includes that request's ID.

## Configure NodeZero Event Collector in Cortex

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

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### nodezero-fetch-events

***
Gets weakness events from done NodeZero pentests, for one pentest or for the pentests that finished since a time. With should_push_events set to true, it also sends to Cortex XSIAM the pentests that the scheduled fetch hasn't sent yet, so you don't have to wait for the next fetch. Pentests that were already sent are shown but never sent again, and the command doesn't send while a scheduled fetch is sending.

#### Base Command

`nodezero-fetch-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command also sends to Cortex XSIAM the events of pentests that weren't sent yet. Each pentest is sent in full. If false, it only displays events. Possible values are: true, false. Default is false. | Required |
| pentest_id | The ID (op_id) of a done pentest to get events for. When set, the since argument is ignored. | Optional |
| limit | The maximum number of events to display. When should_push_events is true, the command doesn't start sending another pentest after it sends this many events, but it always sends a pentest in full, and with pentest_id it sends the whole pentest. Default is 10. | Optional |
| since | Get events from pentests that finished at or after this time, in ISO 8601 or relative format (for example, 3 days). Ignored when pentest_id is set. Default is 7 days. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NodeZero.Event.event_id | String | The unique ID of the event: the pentest op_id and the weakness UUID, separated by a colon. |
| NodeZero.Event._time | Date | The time NodeZero discovered the weakness during the pentest. |
| NodeZero.Event.op_id | String | The ID of the pentest. |
| NodeZero.Event.uuid | String | The ID of the weakness in the pentest. |
| NodeZero.Event.pentest_name | String | The name of the pentest. |
| NodeZero.Event.pentest_type | String | The type of the pentest. |
| NodeZero.Event.pentest_client_name | String | The client name of the pentest. |
| NodeZero.Event.pentest_etl_completed_at | Date | The time the pentest results became available. |
| NodeZero.Event.vuln_id | String | The ID of the weakness type, for example a CVE ID or a NodeZero ID such as H3-2021-0020. |
| NodeZero.Event.vuln_name | String | The name of the weakness type. |
| NodeZero.Event.vuln_short_name | String | The short name of the weakness type. |
| NodeZero.Event.vuln_category | String | The category of the weakness type. |
| NodeZero.Event.vuln_cisa_kev | Boolean | Whether the weakness is in the CISA Known Exploited Vulnerabilities catalog. |
| NodeZero.Event.severity | String | The severity of the weakness: CRITICAL, HIGH, MEDIUM, LOW or INFO. |
| NodeZero.Event.score | Number | The score of the weakness. |
| NodeZero.Event.context_score | Number | The context score of the weakness. |
| NodeZero.Event.has_proof | Boolean | Whether NodeZero proved the weakness. |
| NodeZero.Event.mitre_tactic_ids | Unknown | The MITRE ATT&CK tactic IDs of the weakness. |
| NodeZero.Event.mitre_technique_ids | Unknown | The MITRE ATT&CK technique and sub-technique IDs of the weakness. |
| NodeZero.Event.target_hostname | String | The host name of the affected host. |
| NodeZero.Event.target_ipv4_addresses | Unknown | The IPv4 addresses of the affected host. |
| NodeZero.Event.target_os | String | The operating system of the affected host. |
| NodeZero.Event.portal_url | String | The link to the weakness in the NodeZero Portal. |

#### Usage notes

- When should_push_events is true and a scheduled fetch is sending events, the command returns an error that says when to try again. Run it with should_push_events set to false to view events in the meantime.
- When should_push_events is true and an earlier run stopped partway through a pentest, the command finishes sending that pentest first, even when it isn't in the requested range, and says so in its output.
- When the scheduled fetch is enabled, the command can send events only after the first scheduled fetch of this version has run.

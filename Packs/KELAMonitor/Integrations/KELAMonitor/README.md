Fetches KELA Monitor incidents (hacking discussions, instant messaging, leaked credentials, network vulnerabilities, credit cards and botnets) into Cortex XSOAR.
This integration was integrated and tested with version 1.0 of the KELA Monitor API.

## Configure KELA Monitor in Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for KELA Monitor.
3. Click **Add instance** to create and configure a new integration instance. Create one instance per monitor.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the KELA Monitor API. | True |
| API Token | API token generated in the KELA platform (system menu). It is sent as the apiToken query parameter and is never logged. | True |
| Monitor ID | Numeric ID of the monitor to connect to. It appears in the Monitor module URL, under the monitorId parameter. Create one instance per monitor. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Incidents Fetch Interval |  | False |
| Incident types to fetch | Mandatory: select at least one. Each type keeps its own fetch position. | True |
| First fetch time | How far back to fetch the first time (e.g. "3 days", "12 hours", "2026-10-01T00:00:00Z"). Applied to the incident date. Only used on the first run of each incident type. | False |
| Maximum number of incidents per fetch (per incident type) | Between 1 and 200. | False |
| Fetch only these severities | Optional. Leave empty to fetch every severity. | False |
| Mask sensitive data | When selected (recommended), passwords are replaced by ******** and credit card numbers keep only the BIN and the last 4 digits, both in fetched incidents and in command outputs. Clear it to store the data exactly as KELA returns it. | False |

4. Click **Test** to validate the URL, token and monitor access.

Notes:

- Authentication uses the `apiToken` query parameter. The token is never written to logs or to command outputs.
- The API allows **1 request per second** (HTTP 429 above that). The integration spaces requests and retries on 429.
- Dates in the Monitor API are Unix **seconds**.

## Fetch incidents

For every selected incident type the integration keeps its own *watermark* (the latest `incident_date` fetched) plus the IDs of the incidents that share that exact second, so an incident is never created twice.

- The API returns the newest incidents first, so each cycle reads a whole time window (first request plus scroll pages) and creates the **oldest** incidents first, up to the maximum per fetch.
- Hidden or deleted incidents (flagged by users in KELA's platform) are skipped.
- Hacking discussions only include a text snippet; the full text is not fetched.
- With **Mask sensitive data** selected (default), passwords are replaced by `********` and credit card numbers keep only the BIN and the last 4 digits.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### kela-monitor-incident-list

***
Returns a batch of incidents of one incident type, with optional filters. When more incidents may be available it also returns a scroll ID for kela-monitor-incident-scroll.

#### Base Command

`kela-monitor-incident-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_type | The type of incidents to query. Possible values are: hacking_discussions, instant_messaging, leaked_credentials, network_vulnerabilities, credit_cards, botnets. | Required |
| monitor_id | Monitor ID to query. Defaults to the Monitor ID configured on the instance. | Optional |
| text | Free text to filter results by (same as the free text search on the discovery page). | Optional |
| severities | Severities to return. Comma separated. Possible values are: low, medium, high, critical. | Optional |
| from_date | Minimal date. Accepts ISO dates, relative dates (e.g. "3 days") or a 10 digit epoch in seconds. | Optional |
| to_date | Maximal date. Same formats as from_date. | Optional |
| first_appearance | Leaked credentials only. If true, only returns the first appearance of each credential as tracked by KELA. Best used with a date range. Possible values are: true, false. Default is false. | Optional |
| limit | The maximal number of incidents to return in this batch (1-1000). Default is 20. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KELA.Monitor.Incident.id | String | The incident's ID, usable with the incident data endpoint. |
| KELA.Monitor.Incident.type | String | Incident type; determines which type-specific fields are populated. |
| KELA.Monitor.Incident.sub_type | Unknown | Numeric sub type (integer, or string for some hacking_discussions). |
| KELA.Monitor.Incident.sub_type_description | String | Human-readable sub type. |
| KELA.Monitor.Incident.severity | Number | 1 = low, 2 = medium, 3 = high, 4 = critical. |
| KELA.Monitor.Incident.incident_date | Number | Epoch time (seconds) at which the incident was reported in Monitor. |
| KELA.Monitor.Incident.feed_property_id | String | Aggregation ID the incident belongs to. |
| KELA.Monitor.Incident.feedPropertyId | String | Same as feed_property_id (leaked_credentials, botnets). |
| KELA.Monitor.Incident.assets.id | Number | Related asset ID. |
| KELA.Monitor.Incident.assets.name | String | Related asset name. |
| KELA.Monitor.Incident.assets.type | String | Related asset category. |
| KELA.Monitor.Incident.tags | Unknown | Tags of the incident. |
| KELA.Monitor.Incident.categories | Unknown | Categories of the incident. |
| KELA.Monitor.Incident.user_actions.read | Boolean | Whether the incident was read. |
| KELA.Monitor.Incident.user_actions.star | Boolean | Whether the incident was starred. |
| KELA.Monitor.Incident.user_actions.delete | Boolean | Whether the incident was deleted. |
| KELA.Monitor.Incident.user_actions.handled | Unknown | Name of who handled the incident, or false. |
| KELA.Monitor.Incident.user_actions.hide | Boolean | Whether the incident was hidden. |
| KELA.Monitor.Incident.user_actions.publish | Boolean | Whether the incident was published. |
| KELA.Monitor.Incident.user_actions.request | Boolean | Whether an RFI was requested. |
| KELA.Monitor.Incident.actions.read | Boolean | Same flags as user_actions (not returned for hacking_discussions). |
| KELA.Monitor.Incident.title | String | [hacking_discussions] Incident title. |
| KELA.Monitor.Incident.publish_date | Number | [hacking_discussions] Epoch (seconds) of the original publication. |
| KELA.Monitor.Incident.author | String | [hacking_discussions, instant_messaging] Author of the post or message. |
| KELA.Monitor.Incident.image | String | [hacking_discussions] Screenshot URL. |
| KELA.Monitor.Incident.source | String | [hacking_discussions, credit_cards, botnets, leaked_credentials] Source of the data. |
| KELA.Monitor.Incident.text | String | [hacking_discussions] Text snippet. |
| KELA.Monitor.Incident.posted_date | Number | [leaked_credentials, instant_messaging, credit_cards, botnets] Epoch (seconds) the data was originally published. |
| KELA.Monitor.Incident.email | String | [leaked_credentials] Email address of the credentials. |
| KELA.Monitor.Incident.domain | String | [leaked_credentials] Domain of the email address. |
| KELA.Monitor.Incident.password | String | [leaked_credentials] Password, masked unless Mask sensitive data is cleared. |
| KELA.Monitor.Incident.password_type | String | [leaked_credentials] Type of password. |
| KELA.Monitor.Incident.source_id | String | [leaked_credentials, credit_cards] ID of the original incident. |
| KELA.Monitor.Incident.dump_name | String | [leaked_credentials] Name of the dump. |
| KELA.Monitor.Incident.dump_description | String | [leaked_credentials] Description of the dump. |
| KELA.Monitor.Incident.service | String | [leaked_credentials, network_vulnerabilities, botnets] Service the credentials or port relate to. |
| KELA.Monitor.Incident.ip | String | [network_vulnerabilities] IP address(es). |
| KELA.Monitor.Incident.port | Number | [network_vulnerabilities] Port. |
| KELA.Monitor.Incident.description | String | [network_vulnerabilities] Description of the exposure. |
| KELA.Monitor.Incident.hostname | Unknown | [network_vulnerabilities] Hostnames. |
| KELA.Monitor.Incident.isp | String | [network_vulnerabilities, botnets] ISP. |
| KELA.Monitor.Incident.technology | String | [network_vulnerabilities] Vulnerable technology. |
| KELA.Monitor.Incident.cve_details | String | [network_vulnerabilities] CVEs the technology is vulnerable to. |
| KELA.Monitor.Incident.number | String | [credit_cards] Card number, masked unless Mask sensitive data is cleared. |
| KELA.Monitor.Incident.bin | String | [credit_cards] Card BIN. |
| KELA.Monitor.Incident.bot_id | String | [botnets] Bot identifier. |
| KELA.Monitor.Incident.resource | String | [botnets] Server the credentials were used on. |
| KELA.Monitor.Incident.available_data | Unknown | [botnets] Fields extracted from the bot. |
| KELA.Monitor.Incident.infection_type | String | [botnets] Bot type. |
| KELA.Monitor.Incident.price | Number | [botnets] Bot price on the market. |
| KELA.Monitor.Incident.country | String | [botnets] Country of the infected host. |
| KELA.Monitor.Incident.purchased | Boolean | [botnets] Whether the bot data was purchased. |
| KELA.Monitor.Incident.username | String | [botnets] Username of the compromised account. |
| KELA.Monitor.Incident.source_type | String | [botnets] Type of source of the dump. |
| KELA.Monitor.Incident.file_hash | String | [botnets] Hash of the dump file. |
| KELA.Monitor.Incident.dataId | String | [botnets] Identifier of the data record. |
| KELA.Monitor.Incident.data_id | String | [hacking_discussions, instant_messaging] ID of the underlying post or message. |
| KELA.Monitor.Incident.source_name | String | [instant_messaging] Name of the source. |
| KELA.Monitor.Incident.chat_type | String | [instant_messaging] Chat type. |
| KELA.Monitor.Incident.chat_name | String | [instant_messaging] Chat title. |
| KELA.Monitor.Incident.snippet | String | [instant_messaging] Preview of the message. |
| KELA.Monitor.Incident.full_text | String | [instant_messaging] Full text of the message. |
| KELA.Monitor.Incident.message_id | String | [instant_messaging] Message ID in the source platform. |
| KELA.Monitor.Incident.posted_date_range.min | Number | [instant_messaging] Minimum date, epoch in MILLISECONDS. |
| KELA.Monitor.Incident.posted_date_range.max | Number | [instant_messaging] Maximum date, epoch in MILLISECONDS. |
| KELA.Monitor.Incident.media.url | String | Signed, expiring URL of an attached media item. |
| KELA.Monitor.Incident.media.name | String | Media file name. |
| KELA.Monitor.Incident.media.size | Number | Media size in bytes. |
| KELA.Monitor.Incident.media.hash | String | Media hash. |
| KELA.Monitor.Incident.preview | String | [hacking_discussions] Preview image URL. |
| KELA.Monitor.Incident.pdf | String | [hacking_discussions] PDF capture URL. |
| KELA.Monitor.Incident.source_url | String | [hacking_discussions] URL of the original post. |
| KELA.Monitor.Incident.reasons.type | String | [leaked_credentials] Reason type. |
| KELA.Monitor.Incident.reasons.sub_type | String | [leaked_credentials] Reason sub type. |
| KELA.Monitor.Incident.reasons.value | Unknown | [leaked_credentials] Reason values. |
| KELA.Monitor.Incident.original_data_source_id | String | [leaked_credentials, credit_cards] ID of the original data source. |
| KELA.Monitor.Incident.relevant_date | Number | Epoch (seconds) relevant to the incident. |
| KELA.Monitor.Scroll.scrollId | String | Scroll ID to get the next batch (valid for 2 minutes). |
| KELA.Monitor.Scroll.monitorId | Number | Monitor ID the scroll belongs to. |
| KELA.Monitor.Scroll.incidentType | String | Incident type of the original request (empty when it comes from a scroll). |

#### Command example

```!kela-monitor-incident-list incident_type=leaked_credentials severities=high,critical from_date="7 days" limit=20```

### kela-monitor-incident-scroll

***
Continues a kela-monitor-incident-list request using its scroll ID. Repeat until no incidents are returned. A scroll ID is valid for 2 minutes.

#### Base Command

`kela-monitor-incident-scroll`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scroll_id | The scroll ID returned by kela-monitor-incident-list or by a previous scroll. It is valid for 2 minutes. | Required |
| monitor_id | Monitor ID. Defaults to the Monitor ID configured on the instance. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KELA.Monitor.Incident.id | String | The incident's ID, usable with the incident data endpoint. |
| KELA.Monitor.Incident.type | String | Incident type; determines which type-specific fields are populated. |
| KELA.Monitor.Incident.sub_type | Unknown | Numeric sub type (integer, or string for some hacking_discussions). |
| KELA.Monitor.Incident.sub_type_description | String | Human-readable sub type. |
| KELA.Monitor.Incident.severity | Number | 1 = low, 2 = medium, 3 = high, 4 = critical. |
| KELA.Monitor.Incident.incident_date | Number | Epoch time (seconds) at which the incident was reported in Monitor. |
| KELA.Monitor.Incident.feed_property_id | String | Aggregation ID the incident belongs to. |
| KELA.Monitor.Incident.feedPropertyId | String | Same as feed_property_id (leaked_credentials, botnets). |
| KELA.Monitor.Incident.assets.id | Number | Related asset ID. |
| KELA.Monitor.Incident.assets.name | String | Related asset name. |
| KELA.Monitor.Incident.assets.type | String | Related asset category. |
| KELA.Monitor.Incident.tags | Unknown | Tags of the incident. |
| KELA.Monitor.Incident.categories | Unknown | Categories of the incident. |
| KELA.Monitor.Incident.user_actions.read | Boolean | Whether the incident was read. |
| KELA.Monitor.Incident.user_actions.star | Boolean | Whether the incident was starred. |
| KELA.Monitor.Incident.user_actions.delete | Boolean | Whether the incident was deleted. |
| KELA.Monitor.Incident.user_actions.handled | Unknown | Name of who handled the incident, or false. |
| KELA.Monitor.Incident.user_actions.hide | Boolean | Whether the incident was hidden. |
| KELA.Monitor.Incident.user_actions.publish | Boolean | Whether the incident was published. |
| KELA.Monitor.Incident.user_actions.request | Boolean | Whether an RFI was requested. |
| KELA.Monitor.Incident.actions.read | Boolean | Same flags as user_actions (not returned for hacking_discussions). |
| KELA.Monitor.Incident.title | String | [hacking_discussions] Incident title. |
| KELA.Monitor.Incident.publish_date | Number | [hacking_discussions] Epoch (seconds) of the original publication. |
| KELA.Monitor.Incident.author | String | [hacking_discussions, instant_messaging] Author of the post or message. |
| KELA.Monitor.Incident.image | String | [hacking_discussions] Screenshot URL. |
| KELA.Monitor.Incident.source | String | [hacking_discussions, credit_cards, botnets, leaked_credentials] Source of the data. |
| KELA.Monitor.Incident.text | String | [hacking_discussions] Text snippet. |
| KELA.Monitor.Incident.posted_date | Number | [leaked_credentials, instant_messaging, credit_cards, botnets] Epoch (seconds) the data was originally published. |
| KELA.Monitor.Incident.email | String | [leaked_credentials] Email address of the credentials. |
| KELA.Monitor.Incident.domain | String | [leaked_credentials] Domain of the email address. |
| KELA.Monitor.Incident.password | String | [leaked_credentials] Password, masked unless Mask sensitive data is cleared. |
| KELA.Monitor.Incident.password_type | String | [leaked_credentials] Type of password. |
| KELA.Monitor.Incident.source_id | String | [leaked_credentials, credit_cards] ID of the original incident. |
| KELA.Monitor.Incident.dump_name | String | [leaked_credentials] Name of the dump. |
| KELA.Monitor.Incident.dump_description | String | [leaked_credentials] Description of the dump. |
| KELA.Monitor.Incident.service | String | [leaked_credentials, network_vulnerabilities, botnets] Service the credentials or port relate to. |
| KELA.Monitor.Incident.ip | String | [network_vulnerabilities] IP address(es). |
| KELA.Monitor.Incident.port | Number | [network_vulnerabilities] Port. |
| KELA.Monitor.Incident.description | String | [network_vulnerabilities] Description of the exposure. |
| KELA.Monitor.Incident.hostname | Unknown | [network_vulnerabilities] Hostnames. |
| KELA.Monitor.Incident.isp | String | [network_vulnerabilities, botnets] ISP. |
| KELA.Monitor.Incident.technology | String | [network_vulnerabilities] Vulnerable technology. |
| KELA.Monitor.Incident.cve_details | String | [network_vulnerabilities] CVEs the technology is vulnerable to. |
| KELA.Monitor.Incident.number | String | [credit_cards] Card number, masked unless Mask sensitive data is cleared. |
| KELA.Monitor.Incident.bin | String | [credit_cards] Card BIN. |
| KELA.Monitor.Incident.bot_id | String | [botnets] Bot identifier. |
| KELA.Monitor.Incident.resource | String | [botnets] Server the credentials were used on. |
| KELA.Monitor.Incident.available_data | Unknown | [botnets] Fields extracted from the bot. |
| KELA.Monitor.Incident.infection_type | String | [botnets] Bot type. |
| KELA.Monitor.Incident.price | Number | [botnets] Bot price on the market. |
| KELA.Monitor.Incident.country | String | [botnets] Country of the infected host. |
| KELA.Monitor.Incident.purchased | Boolean | [botnets] Whether the bot data was purchased. |
| KELA.Monitor.Incident.username | String | [botnets] Username of the compromised account. |
| KELA.Monitor.Incident.source_type | String | [botnets] Type of source of the dump. |
| KELA.Monitor.Incident.file_hash | String | [botnets] Hash of the dump file. |
| KELA.Monitor.Incident.dataId | String | [botnets] Identifier of the data record. |
| KELA.Monitor.Incident.data_id | String | [hacking_discussions, instant_messaging] ID of the underlying post or message. |
| KELA.Monitor.Incident.source_name | String | [instant_messaging] Name of the source. |
| KELA.Monitor.Incident.chat_type | String | [instant_messaging] Chat type. |
| KELA.Monitor.Incident.chat_name | String | [instant_messaging] Chat title. |
| KELA.Monitor.Incident.snippet | String | [instant_messaging] Preview of the message. |
| KELA.Monitor.Incident.full_text | String | [instant_messaging] Full text of the message. |
| KELA.Monitor.Incident.message_id | String | [instant_messaging] Message ID in the source platform. |
| KELA.Monitor.Incident.posted_date_range.min | Number | [instant_messaging] Minimum date, epoch in MILLISECONDS. |
| KELA.Monitor.Incident.posted_date_range.max | Number | [instant_messaging] Maximum date, epoch in MILLISECONDS. |
| KELA.Monitor.Incident.media.url | String | Signed, expiring URL of an attached media item. |
| KELA.Monitor.Incident.media.name | String | Media file name. |
| KELA.Monitor.Incident.media.size | Number | Media size in bytes. |
| KELA.Monitor.Incident.media.hash | String | Media hash. |
| KELA.Monitor.Incident.preview | String | [hacking_discussions] Preview image URL. |
| KELA.Monitor.Incident.pdf | String | [hacking_discussions] PDF capture URL. |
| KELA.Monitor.Incident.source_url | String | [hacking_discussions] URL of the original post. |
| KELA.Monitor.Incident.reasons.type | String | [leaked_credentials] Reason type. |
| KELA.Monitor.Incident.reasons.sub_type | String | [leaked_credentials] Reason sub type. |
| KELA.Monitor.Incident.reasons.value | Unknown | [leaked_credentials] Reason values. |
| KELA.Monitor.Incident.original_data_source_id | String | [leaked_credentials, credit_cards] ID of the original data source. |
| KELA.Monitor.Incident.relevant_date | Number | Epoch (seconds) relevant to the incident. |
| KELA.Monitor.Scroll.scrollId | String | Scroll ID to get the next batch (valid for 2 minutes). |
| KELA.Monitor.Scroll.monitorId | Number | Monitor ID the scroll belongs to. |
| KELA.Monitor.Scroll.incidentType | String | Incident type of the original request (empty when it comes from a scroll). |

#### Command example

```!kela-monitor-incident-scroll scroll_id=<SCROLL_ID>```

#### Human Readable Output (illustrative, not run against the live API)

>### KELA Monitor incidents (leaked_credentials) (1 returned)
>
>|ID|Type|Sub Type|Severity|Incident Date|Tags|
>|---|---|---|---|---|---|
>| `<incident-id>` | leaked_credentials | Leaked Credentials From Instant Messaging | 3 | 2026-10-03T14:21:07Z | example.com |

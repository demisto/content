Use the KELA Monitor integration to fetch the incidents of a KELA Monitor (hacking discussions, instant messaging, leaked credentials, network vulnerabilities, credit cards and compromised accounts) into Cortex and to list them on demand.

KELA Monitor is the successor of KELA RaDark (KELA renamed the RaDark module to Monitor). If a KELA RaDark instance fetches the same monitor, disable it before you enable fetching here, otherwise every KELA incident is created twice. The two integrations do not share context paths (`Radark.*` there, `KELA.Monitor.*` here), incident types, fields, mappers or layouts: this pack ships its own. The integration is read-only: it never changes anything in KELA.

## Terms

The KELA Monitor API uses three terms:

- **Monitor**: the KELA entity that raises alerts when data from KELA's sources matches the patterns configured for your assets. It is identified by its numeric Monitor ID.
- **Incident**: one data point that matched a pattern of the monitor (a post, a message, a credential, a card, a bot, an exposed host). Each incident has its own ID and is fetched as one Cortex incident.
- **Aggregation**: the alert that bundles one or more incidents in the KELA platform. Its ID is the incident's `feed_property_id`, shown in the **KELA Monitor Aggregation ID** field, and you can search for it in the KELA platform.

## Before you start

- Use a **dedicated KELA platform user** for the integration. The API token is per user: it carries that user's access to monitors and incident types, and it can be rotated. Generate it in the KELA platform under **Settings** (bottom-left) > **API access**.
- Get the **Monitor ID** from the browser address bar while you view the monitor in the KELA platform (the `monitorId` parameter). Create one instance per monitor.
- Check which incident types your Monitor license includes. Types without access answer 403: **Test** names them, and fetch skips them.

| Incident type in the KELA platform | Value of *Incident types to fetch* / `incident_type` | Cortex incident type | Note |
| --- | --- | --- | --- |
| Hacking Discussion | hacking_discussions | KELA Monitor Hacking Discussion | Fetched as a text snippet, not the full post. |
| Instant Messaging | instant_messaging | KELA Monitor Instant Messaging | |
| Leaked Credentials | leaked_credentials | KELA Monitor Leaked Credentials | Needs the matching KELA license. |
| Network Vulnerability | network_vulnerabilities | KELA Monitor Network Vulnerability | |
| Credit Cards | credit_cards | KELA Monitor Credit Cards | |
| Compromised Accounts | botnets | KELA Monitor Compromised Accounts | The API calls this type `botnets`. Needs the matching KELA license. |
| Intelligence Report | not available | | Not fetched by this integration. |
| Data-Loss Detection | not available | | Not fetched by this integration. |

## Configure KELA Monitor in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for KELA Monitor.
3. Click **Add instance** to create and configure a new integration instance. Create one instance per monitor.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the KELA Monitor API. | True |
| API Token | API token of a dedicated KELA platform user, generated under Settings (bottom-left) > API access. The token is per user and can be rotated. It is sent in the apiToken HTTP header (not in the URL) and is masked in the integration's logs and error messages. | True |
| Monitor ID | Numeric ID of the monitor to connect to. It appears in the Monitor module URL, under the monitorId parameter. Create one instance per monitor. | True |
| Trust any certificate (not secure) | When selected, certificates are not checked (not secure). Use it only for testing. | False |
| Use system proxy settings | When selected, requests go through the proxy configured on the server or engine. | False |
| Fetch incidents | Creates a Cortex incident for every new KELA Monitor incident of the selected incident types. | False |
| Incident type | Leave empty. The KELA Monitor classifier sets one Cortex incident type per KELA incident type. | False |
| Incidents Fetch Interval | How often a fetch cycle runs. A cycle may take several minutes when it reads a large backlog. | False |
| Incident types to fetch | Required when Fetch incidents is selected; select at least one type available in your Monitor license. botnets is the Compromised Accounts type of the KELA platform. Each type keeps its own fetch position. | False |
| First fetch time | How far back to fetch the first time (e.g. "3 days", "12 hours", "2026-10-01T00:00:00Z"). Applied to the incident date. Only used on the first run of each incident type. | False |
| Maximum number of incidents per fetch (per incident type) | Between 1 and 200. | False |
| Fetch only these severities | Optional. Leave empty to fetch every severity. | False |
| Mask sensitive data | When selected (recommended), the leaked email and compromised user name are shortened in incident names (j***@example.com), passwords, cookies, tokens, sessions, secrets and CVVs are replaced by ******** and credit card numbers keep only the BIN and the last 4 digits, both in fetched incidents and in command outputs. Clear it to store the data exactly as KELA returns it. The masked incident fields stay masked either way. | False |
| Do not create incidents already handled in KELA | When selected, incidents that a user already marked as handled in the KELA platform are not created. They still move the fetch position forward, so they are not created later either. | False |

4. Click **Test** to validate the URL, token, monitor access and, when fetch is selected, the fetch settings.

## Fetch incidents

Each selected incident type is fetched on its own and keeps its own position, so adding a type later does not fetch the others again.

**What a fetched incident looks like**

- **Name**: `KELA Monitor - <type>: <summary> [<KELA incident ID>]`. The summary is the title, chat, email, host, masked card or bot, depending on the type; it never contains a password or a full card number. With **Mask sensitive data** selected the leaked email and the compromised user name are shortened (`j***@example.com`).
- **Occurred**: the KELA `incident_date` (when the incident was reported in the monitor), in UTC.
- **Severity**: the KELA severity (1 Low, 2 Medium, 3 High, 4 Critical) maps to the same Cortex severity; a missing or unknown value becomes Low.
- **Details**: the text or snippet of the incident, without KELA's highlight tags (for instant messaging, the full message when KELA returns it).
- **Type, fields and layout**: the **KELA Monitor - Classifier** sets one incident type per KELA incident type (see the table above; other values get **KELA Monitor Incident**), and the **KELA Monitor - Incoming Mapper** fills the **KELA Monitor ...** incident fields shown by the layout of each type. Raw KELA attributes are not copied to incident labels.
- **Raw JSON**: the KELA incident as returned by the API (masked when **Mask sensitive data** is selected), plus a `kelaMeta` object with the Monitor ID, the posting date in ISO format and always-masked copies of passwords, card numbers and bot data for the mapper.
- **Fetch History** shows the KELA incident ID as the source ID.

**How much is fetched per cycle**

- Up to *Maximum number of incidents per fetch* incidents per incident type (default 50, maximum 200), so a cycle with all six types selected creates up to 300 incidents with the default value.
- KELA returns the newest incidents first, so each cycle reads a whole time window (one request plus scroll pages, at most 20 API calls per type) and creates the oldest incidents first. The first fetch drains the *First fetch time* backlog over as many cycles as it needs, oldest first.
- The KELA API allows 1 request per second. When it answers 429 the integration retries with a growing delay, so a cycle that reads a large backlog can take a few minutes.
- Incidents hidden or deleted by a user in the KELA platform are not created. With **Do not create incidents already handled in KELA** selected, incidents marked as handled in KELA are not created either.
- Incidents that KELA reports with the same second as the last fetched one are tracked by ID, so none is created twice.

**Sensitive data**

With **Mask sensitive data** selected (default), passwords, cookies, tokens, sessions, secrets and CVVs are replaced by `********` at any depth, and credit card numbers keep only the BIN and the last 4 digits, both in fetched incidents and in command outputs. The **KELA Monitor Password Masked**, **KELA Monitor Card Number Masked** and **KELA Monitor Available Data** fields are always masked, even when the option is cleared. Free text (posts, messages) is never masked.

## Context outputs

- Dates are returned as ISO 8601 UTC strings (for example `2026-10-05T00:52:18Z`), not as the epoch values of the API.
- The API returns some keys twice: `feedPropertyId` repeats `feed_property_id` (leaked_credentials, botnets), and botnets use `dataId` where the other types use `data_id`. Both spellings are kept as returned by KELA.
- Each list or scroll call that may have more results adds a `KELA.Monitor.Scroll` entry. A scroll ID is valid for 2 minutes. In a playbook or automation, run `kela-monitor-incident-list`, then `kela-monitor-incident-scroll` with the scroll ID from `KELA.Monitor.Scroll.scrollId`, and repeat the scroll until it returns no incidents.

## Commands and security notes

- `kela-monitor-incident-list` prints every returned incident in the War Room: keep `limit` at 100 or less when you run it manually.
- The `monitor_id` argument can query any monitor the token's user can access, not only the instance's monitor. Use a dedicated user that only has the monitors this instance needs.
- `source_url` (hacking discussions, instant messaging) points to the original post and may be an .onion address. Do not open it from the corporate network. The `image`, `preview`, `pdf` and `media.url` links are signed and expire.
- The Server URL must use https. The token is sent in the `apiToken` header, registered for log masking and removed from the error messages of the integration.

## Known limitations

- **Intelligence Report and Data-Loss Detection** incidents are not fetched: their API identifiers and field layout are waiting for KELA's confirmation. Any other KELA incident type that reaches Cortex gets the **KELA Monitor Incident** type.
- **No link back to the KELA platform**: KELA has not documented a URL pattern for a single incident yet. Use the **KELA Monitor Aggregation ID** to find the incident in the KELA platform.
- **Command examples**: the examples in this README have no sample output yet. The output will be added from a run against a licensed monitor.
- **Very large same-second groups**: KELA dates have one-second precision. When more than 500 incidents share one second, the integration replaces the stored ID list of that second by an ID cursor. An incident that KELA adds to that second later, with an ID that sorts before the cursor, is not fetched.
- **Monitor scope of the commands**: the `monitor_id` argument can query any monitor the token's user can access. Use a dedicated user that only has the monitors this instance needs.
- Free text (posts, messages) is stored as KELA returns it; only the keyed values listed above are masked.
- Status is not synchronised in either direction: the KELA read and starred flags do not change what is fetched (only hidden, deleted and, optionally, handled incidents are skipped), and closing a Cortex incident does not mark it as handled in KELA.

## Troubleshooting

- **Authorization Error**: the token is wrong, expired or was rotated. Generate a new one under **Settings** > **API access**.
- **Forbidden [403]**: the token's user has no access to this monitor or to this incident type (license). When only some selected types are forbidden, **Test** does not return a success: it names the forbidden types (fetch still works for the others). Unselect them to make **Test** succeed.
- **Not Found**: wrong Monitor ID, or a scroll ID older than 2 minutes.

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
| monitor_id | Monitor ID to query. Defaults to the Monitor ID configured on the instance. Any monitor the token's user can access can be queried. | Optional |
| text | Free text to filter results by (same as the free text search on the discovery page). | Optional |
| severities | A comma-separated list of severities to return. Possible values are: low, medium, high, critical. | Optional |
| from_date | Minimal date. Accepts ISO dates, relative dates (e.g. "3 days") or a 10 digit epoch in seconds. | Optional |
| to_date | Maximal date. Same formats as from_date. | Optional |
| first_appearance | Whether to return only the first appearance of each credential as tracked by KELA (leaked credentials only). Best used with a date range. Possible values are: true, false. Default is false. | Optional |
| limit | The maximal number of incidents to return in this batch (1-1000). Every incident is printed in the War Room, so keep it at 100 or less when you run the command manually. Default is 20. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KELA.Monitor.Incident.id | String | The ID of the incident in KELA Monitor. |
| KELA.Monitor.Incident.type | String | Incident type; determines which type-specific fields are populated. |
| KELA.Monitor.Incident.sub_type | Unknown | Numeric sub type (integer, or string for some hacking_discussions). |
| KELA.Monitor.Incident.sub_type_description | String | Human-readable sub type. |
| KELA.Monitor.Incident.severity | Number | 1 = low, 2 = medium, 3 = high, 4 = critical. |
| KELA.Monitor.Incident.incident_date | Date | The date and time (ISO 8601, UTC) at which the incident was reported in Monitor. |
| KELA.Monitor.Incident.feed_property_id | String | Aggregation ID the incident belongs to. |
| KELA.Monitor.Incident.feedPropertyId | String | Same value as feed_property_id, returned by the API in camelCase as well (leaked_credentials, botnets). |
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
| KELA.Monitor.Incident.publish_date | Date | [hacking_discussions] The date and time (ISO 8601, UTC) of the original publication. |
| KELA.Monitor.Incident.author | String | [hacking_discussions, instant_messaging] Author of the post or message. |
| KELA.Monitor.Incident.image | String | [hacking_discussions] Screenshot URL. |
| KELA.Monitor.Incident.source | String | [hacking_discussions, credit_cards, botnets, leaked_credentials] Source of the data. |
| KELA.Monitor.Incident.text | String | [hacking_discussions] Text snippet. |
| KELA.Monitor.Incident.posted_date | Date | [leaked_credentials, instant_messaging, credit_cards, botnets] The date and time (ISO 8601, UTC) the data was originally published. |
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
| KELA.Monitor.Incident.dataId | String | [botnets] Identifier of the data record (the API uses dataId for botnets and data_id for other types). |
| KELA.Monitor.Incident.data_id | String | [hacking_discussions, instant_messaging] ID of the underlying post or message. |
| KELA.Monitor.Incident.source_name | String | [instant_messaging] Name of the source. |
| KELA.Monitor.Incident.chat_type | String | [instant_messaging] Chat type. |
| KELA.Monitor.Incident.chat_name | String | [instant_messaging] Chat title. |
| KELA.Monitor.Incident.snippet | String | [instant_messaging] Preview of the message. |
| KELA.Monitor.Incident.full_text | String | [instant_messaging] Full text of the message. |
| KELA.Monitor.Incident.message_id | String | [instant_messaging] Message ID in the source platform. |
| KELA.Monitor.Incident.posted_date_range.min | Date | [instant_messaging] The earliest date and time (ISO 8601, UTC) of the message range. |
| KELA.Monitor.Incident.posted_date_range.max | Date | [instant_messaging] The latest date and time (ISO 8601, UTC) of the message range. |
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
| KELA.Monitor.Incident.relevant_date | Date | The date and time (ISO 8601, UTC) relevant to the incident. |
| KELA.Monitor.Scroll.scrollId | String | Scroll ID to get the next batch (valid for 2 minutes). |
| KELA.Monitor.Scroll.monitorId | Number | Monitor ID the scroll belongs to. |
| KELA.Monitor.Scroll.incidentType | String | Incident type of the original request (empty when it comes from a scroll). |

#### Command example

```!kela-monitor-incident-list incident_type=hacking_discussions limit=2```

```!kela-monitor-incident-list incident_type=instant_messaging text="example.com" from_date="30 days" limit=5```

```!kela-monitor-incident-list incident_type=leaked_credentials severities=high,critical from_date="7 days" first_appearance=true limit=20```

### kela-monitor-incident-scroll

***
Continues a kela-monitor-incident-list request using its scroll ID. Repeat until no incidents are returned. A scroll ID is valid for 2 minutes.

#### Base Command

`kela-monitor-incident-scroll`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scroll_id | The scroll ID returned by kela-monitor-incident-list or by a previous scroll. It is valid for 2 minutes. | Required |
| monitor_id | Monitor ID. Defaults to the Monitor ID configured on the instance. Any monitor the token's user can access can be queried. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KELA.Monitor.Incident.id | String | The ID of the incident in KELA Monitor. |
| KELA.Monitor.Incident.type | String | Incident type; determines which type-specific fields are populated. |
| KELA.Monitor.Incident.sub_type | Unknown | Numeric sub type (integer, or string for some hacking_discussions). |
| KELA.Monitor.Incident.sub_type_description | String | Human-readable sub type. |
| KELA.Monitor.Incident.severity | Number | 1 = low, 2 = medium, 3 = high, 4 = critical. |
| KELA.Monitor.Incident.incident_date | Date | The date and time (ISO 8601, UTC) at which the incident was reported in Monitor. |
| KELA.Monitor.Incident.feed_property_id | String | Aggregation ID the incident belongs to. |
| KELA.Monitor.Incident.feedPropertyId | String | Same value as feed_property_id, returned by the API in camelCase as well (leaked_credentials, botnets). |
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
| KELA.Monitor.Incident.publish_date | Date | [hacking_discussions] The date and time (ISO 8601, UTC) of the original publication. |
| KELA.Monitor.Incident.author | String | [hacking_discussions, instant_messaging] Author of the post or message. |
| KELA.Monitor.Incident.image | String | [hacking_discussions] Screenshot URL. |
| KELA.Monitor.Incident.source | String | [hacking_discussions, credit_cards, botnets, leaked_credentials] Source of the data. |
| KELA.Monitor.Incident.text | String | [hacking_discussions] Text snippet. |
| KELA.Monitor.Incident.posted_date | Date | [leaked_credentials, instant_messaging, credit_cards, botnets] The date and time (ISO 8601, UTC) the data was originally published. |
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
| KELA.Monitor.Incident.dataId | String | [botnets] Identifier of the data record (the API uses dataId for botnets and data_id for other types). |
| KELA.Monitor.Incident.data_id | String | [hacking_discussions, instant_messaging] ID of the underlying post or message. |
| KELA.Monitor.Incident.source_name | String | [instant_messaging] Name of the source. |
| KELA.Monitor.Incident.chat_type | String | [instant_messaging] Chat type. |
| KELA.Monitor.Incident.chat_name | String | [instant_messaging] Chat title. |
| KELA.Monitor.Incident.snippet | String | [instant_messaging] Preview of the message. |
| KELA.Monitor.Incident.full_text | String | [instant_messaging] Full text of the message. |
| KELA.Monitor.Incident.message_id | String | [instant_messaging] Message ID in the source platform. |
| KELA.Monitor.Incident.posted_date_range.min | Date | [instant_messaging] The earliest date and time (ISO 8601, UTC) of the message range. |
| KELA.Monitor.Incident.posted_date_range.max | Date | [instant_messaging] The latest date and time (ISO 8601, UTC) of the message range. |
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
| KELA.Monitor.Incident.relevant_date | Date | The date and time (ISO 8601, UTC) relevant to the incident. |
| KELA.Monitor.Scroll.scrollId | String | Scroll ID to get the next batch (valid for 2 minutes). |
| KELA.Monitor.Scroll.monitorId | Number | Monitor ID the scroll belongs to. |
| KELA.Monitor.Scroll.incidentType | String | Incident type of the original request (empty when it comes from a scroll). |

#### Command example

```!kela-monitor-incident-scroll scroll_id=${KELA.Monitor.Scroll.scrollId} monitor_id=${KELA.Monitor.Scroll.monitorId}```

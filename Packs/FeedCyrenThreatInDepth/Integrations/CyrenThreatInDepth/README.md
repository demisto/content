Threat InDepth's correlated and contextualized intelligence helps enterprises improve their threat detection and response by providing unprecedented visibility into new email-borne security threats and actionable insights to make meaningful response decisions. By correlating insights gathered across email content, web traffic, and suspicious files; Cyren provides security teams with a multi-dimensional presentation of critical threat characteristics.

##### Benefits include

- Access to Cyren's GlobalView™ Threat Intelligence Cloud that provides the earliest visibility into new and evolving attacks on a global basis
- Comprehensive, multi-dimensional presentation of critical threat characteristics to help analysts understand the evolving threat landscape
- Timely, Correlated, & Contextualized intelligence that helps reduce mean-time-to-detect (MTTD) and mean-time-to-respond (MTTR) for security analysts
- Improved threat detection for existing security products such as SIEM and SOAR solutions

##### Feeds included in Cyren Threat InDepth content pack
The Cyren Threat InDepth content pack includes access to these streams of indicators:

- IP Reputation Intelligence
- Phishing & Fraud URL Intelligence
- Malware URL Intelligence
- Malware File Intelligence

## Configure Cyren Threat InDepth Threat Intelligence Feed In Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apikey | API JWT token that has been issued to you | True |
| feed_name | Name of the particular feed that matches your API JWT token | True |
| max_indicators | The maximum number of indicators to fetch | False |
| feed | Fetch indicators. | False |
| feedIncremental | Is incremental or not | False |
| feedReputation | The reputation to apply to the fetched indicators. | False |
| feedReliability | The reliability of the this feed. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | | False |
| feedExpirationInterval | | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |


The underlying Cyren Threat InDepth API provides you with an incremental feed, meaning it provides new
or modified indicators. It also works with an offset value that keeps track of your currently processed
indicators. Your current offset defaults at the globally known maximum offset on your first setup and
is being stored and updated for you in the integration instance context. The integration then uses the
"Maximum number of indicators" parameter as the count in each request. It is recommended to set it to
a high enough value so that you get all the feed indicators for maximum product value, to handle bursts
etc. (the value cannot be higher than 100.000 and it will be capped at that value if you set a higher one).

In case you want to want to reset the offset value, use the `cyren-threat-indepth-reset-client-offset` command.

You can retrieve the current offset value using the `cyren-threat-indepth-get-client-offset` command.

## Commands

You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Fetch indicators

Fetching Cyren Threat InDepth indicators

##### Required Permissions

- A valid API JWT token and a matching feed name

##### Base Command

`cyren-threat-indepth-get-indicators`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_indicators | The maximum number of results to return. | True |

##### Context Output

There is no context output for this command.

##### Command Example
`!cyren-threat-indepth-get-indicators max_indicators=2`

##### Human Readable Output

Indicators from Cyren Threat InDepth:

|value|type|rawJSON|score|
|---|---|---|---|
| http://nu4vs0m.u5jkzm4r.i2wd30t.bpbp9c7d.b7ni2cio.auz8x15h.freshoff.eu | URL | `payload: {"action": "+", "type": "url", "identifier": "f59ef036-a790-5193-b942-24a8618c936a", "first_seen": "2020-10-25T13:41:36.000Z", "last_seen": "2021-01-05T13:54:41.000Z", "detection": {"category": ["phishing"], "detection_ts": "2020-10-25T13:41:36.000Z"}, "meta": {"port": 80, "protocol": "http"}, "relationships": [{"relationship_type": "resolves to", "relationship_ts": "2020-10-25T13:41:36.000Z", "ip": "217.70.142.108", "related_entity_category": "phishing", "relationship_description": "resolves to phishing ip"}], "detection_methods": ["URL Categorization"], "url": "http://nu4vs0m.u5jkzm4r.i2wd30t.bpbp9c7d.b7ni2cio.auz8x15h.freshoff.eu"} offset: 57006380 timestamp: 2021-01-05T14:00:48.919Z` | 3 |

### Reset Client Offset

This command allows you to update the stored client offset for the feed API.

##### Required Permissions

- A valid API JWT token and a matching feed name

##### Base Command

`cyren-threat-indepth-reset-client-offset`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | *Optional* The offset you want to use as your baseline for future fetches (if not provided, the global max offset from the API is used) | False |

##### Context Output

There is no context output for this command.

##### Command Example
`!cyren-threat-indepth-reset-client-offset`
`!cyren-threat-indepth-reset-client-offset offset = 34234234`

##### Human Readable Output

Reset Cyren Threat InDepth ip_reputation feed client offset to 1000 (API provided max offset of 1000, was 500).

### Get Client Offset

This command allows you to retrieve the stored client offset for the feed API.

##### Required Permissions

- A valid API JWT token and a matching feed name

##### Base Command

`cyren-threat-indepth-get-client-offset`

##### Input

There is not input for this command.

##### Context Output

There is no context output for this command.

##### Command Example
`!cyren-threat-indepth-get-client-offset`

##### Human Readable Output

Cyren Threat InDepth ip_reputation feed client offset is 500 (API provided max offset of 1000).

## Additional Information

Contact us: support@cyren.com
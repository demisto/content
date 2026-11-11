Cognyte is a global leader in security analytics software that empowers governments and enterprises with Actionable
Intelligence for a safer world. Luminar is Cognyte's asset-based cybersecurity intelligence platform that enables
organizations to build and maintain a proactive threat intelligence operation.

This integration fetches intelligence-based IOCs and customer-related leaked records identified by Luminar, using the
Luminar TAXII 2.1 external API (STIX 2.1). It creates indicators from the `IOCs` and `Leaked Records` collections
(STIX `incident` objects become `Luminar Incident` indicators) and creates STIX relationships as separate
relationship edges.
This integration was integrated and tested with the Luminar external API (TAXII 2.1).

## Configure Cognyte Luminar V3 Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Luminar Base URL | The Luminar API base URL. | True |
| Luminar API Account ID | The Luminar API account ID \(TAXII realm name\). | True |
| Client ID | The Luminar API client credentials. The Client ID goes in the identifier field and the Client Secret in the password field. | True |
| Client Secret |  | True |
| Use system proxy settings | Whether to use the system proxy settings. | False |
| Trust any certificate (not secure) | Whether to trust any certificate \(not secure\). | False |
| First Fetch Time | The first fetch time range or date for incremental fetching \(e.g. "7 days", "2026-01-01T00:00:00Z"\). On the first fetch, indicators added to the collections after this time are ingested. | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval | The interval \(in minutes\) at which the feed fetches indicators. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Include Leaked Credentials | Whether to store the plaintext leaked credential in the Account indicator's Luminar Leaked Credential field. When not selected, a masked value is stored so customer passwords are not exposed in TIM. | False |
| Bypass exclusion list | Whether to bypass the exclusion list for indicators from this feed. When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### luminar-v3-get-indicators

***
Gets Luminar indicators from the IOCs collection. Related objects' fields are appended as `<stix-type>-<field>` columns (e.g. malware-Value, threat-actor-aliases).

#### Base Command

`luminar-v3-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional |
| from_date | The date from which to return objects added to the collection (used as the TAXII "added_after" filter). Accepts a date range (e.g. "7 days") or an ISO date (e.g. "2026-01-01T00:00:00Z"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LuminarV3.Indicators.Type | String | The indicator type. |
| LuminarV3.Indicators.Value | String | The indicator value. |
| LuminarV3.Indicators.Occurred | Date | The date the indicator occurred in ISO 8601 format \(e.g. 2026-01-15T12:34:56Z\). |
| LuminarV3.Indicators.stixid | String | The STIX ID of the indicator object. |
| LuminarV3.Indicators.tags | String | The indicator tags. |
| LuminarV3.Indicators.luminarscore | Number | The Luminar score of the indicator. |
| LuminarV3.Indicators.description | String | The indicator description. |
| LuminarV3.Indicators.confidence | String | The indicator confidence. |
| LuminarV3.Indicators.malwarefamily | String | The malware family associated with the indicator. |
| LuminarV3.Indicators.actor | String | The threat actors associated with the indicator. |

#### Command example

```!luminar-v3-get-indicators limit="1" from_date="7 days"```

#### Context Example

```json
{
    "LuminarV3": {
        "Indicators": [
            {
                "Type": "IP",
                "Value": "200.41.233.229",
                "Occurred": "2026-09-08T00:00:00.000Z",
                "stixid": "indicator--73be9a1f-266b-5023-9c6d-a23c955b65cb",
                "confidence": "90",
                "creationdate": "2026-09-08T00:00:00.000Z",
                "updateddate": "2026-09-09T00:00:58.072Z",
                "reportedby": [
                    "Luminar"
                ],
                "luminarcollectiondate": "2026-09-09T00:00:02.718Z",
                "validfrom": "2026-09-08T00:00:00.000Z",
                "tags": [
                    "SuspiciousNetworkActivity",
                    "Scanner",
                    "phishing",
                    "bruteforce",
                    "bad_reputation"
                ],
                "luminarscore": 100,
                "luminarvaliduntil": "2026-09-15T00:00:00.000Z",
                "luminarconvictionreasons": "bad_reputation",
                "luminarprotocols": "ssh",
                "luminarthreattypes": "bruteforce",
                "luminartargetedsystems": "Attack",
                "luminarcloudprovider": false,
                "asn": "10834",
                "geocountry": "US"
            }
        ]
    }
}
```

#### Human Readable Output

>### Luminar Indicator
>
>|Type|Value|Occurred|Confidence|Creation Date|Updated Date|Reported By|Luminar Collection Date|Valid From|Tags|Luminar Score|Luminar Valid Until|Luminar Conviction Reasons|Luminar Protocols|Luminar Threat Types|Luminar Targeted Systems|Luminar Cloud Provider|ASN|Geo Country|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| IP | 200.41.233.229 | 2026-09-08T00:00:00.000Z | 90 | 2026-09-08T00:00:00.000Z | 2026-09-09T00:00:58.072Z | Luminar | 2026-09-09T00:00:02.718Z | 2026-09-08T00:00:00.000Z | SuspiciousNetworkActivity,<br>Scanner,<br>phishing,<br>bruteforce,<br>bad_reputation | 100 | 2026-09-15T00:00:00.000Z | bad_reputation | ssh | bruteforce | Attack | false | 10834 | US |
>
>**13 indicators saved to TIM.**

### luminar-v3-get-leaked-records

***
Gets Luminar leaked records (leaked credentials) from the Leaked Records collection. Related objects' fields are appended as `<stix-type>-<field>` columns (e.g. incident-name, incident-luminarthreatscore).

#### Base Command

`luminar-v3-get-leaked-records`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of leaked records to return. Default is 50. | Optional |
| from_date | The date from which to return objects added to the collection (used as the TAXII "added_after" filter). Accepts a date range (e.g. "7 days") or an ISO date (e.g. "2026-01-01T00:00:00Z"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LuminarV3.LeakedCredentials.Type | String | The indicator type \(Account\). |
| LuminarV3.LeakedCredentials.Value | String | The account login of the leaked credential. |
| LuminarV3.LeakedCredentials.Occurred | Date | The date the record occurred in ISO 8601 format \(e.g. 2026-01-15T12:34:56Z\). |
| LuminarV3.LeakedCredentials.stixid | String | The STIX ID of the user-account object. |
| LuminarV3.LeakedCredentials.accounttype | String | The account type \(LEAKED CREDENTIAL\). |
| LuminarV3.LeakedCredentials.username | String | The account login. |
| LuminarV3.LeakedCredentials.emailaddress | String | The email address associated with the leaked account. |
| LuminarV3.LeakedCredentials.luminarleakedcredential | String | The leaked credential. |
| LuminarV3.LeakedCredentials.luminarleaksource | String | The source where the credential was leaked. |
| LuminarV3.LeakedCredentials.luminarleakurl | String | The URL associated with the leaked credential. |
| LuminarV3.LeakedCredentials.luminarincidentname | String | The name of the related Luminar incident. |
| LuminarV3.LeakedCredentials.luminarincidentdescription | String | The description of the related Luminar incident. |
| LuminarV3.LeakedCredentials.luminarthreatscore | Number | The Luminar threat score of the related incident. |
| LuminarV3.LeakedCredentials.luminarcomputername | String | The computer name associated with the leaked record. |
| LuminarV3.LeakedCredentials.luminarcollectiondate | Date | The date the record was collected by Luminar in ISO 8601 format \(e.g. 2026-01-15T12:34:56Z\). |
| LuminarV3.LeakedCredentials.tags | String | The record tags. |

#### Command example

```!luminar-v3-get-leaked-records limit="1" from_date="2025-01-01T00:00:00Z"```

#### Context Example

```json
{
    "LuminarV3": {
        "LeakedCredentials": [
            {
                "Type": "Account",
                "Value": "john.doe@example.com",
                "Occurred": "2025-04-01T00:00:00.000Z",
                "stixid": "user-account--72bf90c1-9e95-55b9-afda-e6042d40a9f6",
                "reportedby": [
                    "Luminar"
                ],
                "tags": [
                    "LEAKED CREDENTIAL",
                    "Incident: Example_Leak_Bundle.zip"
                ],
                "category": "LEAKED CREDENTIAL",
                "accounttype": "LEAKED CREDENTIAL",
                "username": "john.doe@example.com",
                "displayname": "john.doe@example.com",
                "emailaddress": "john.doe@example.com",
                "luminarleakedcredential": "********",
                "luminarleaksource": "telegram",
                "luminarleakurl": "www.example.com/register",
                "luminarmonitoringplanterms": "example.com",
                "luminarcredentialisfresh": false,
                "creationdate": "2025-04-01T00:00:00.000Z",
                "updateddate": "2026-09-09T04:19:40.838Z",
                "luminarincidentname": "Example_Leak_Bundle.zip",
                "luminarincidentdescription": "The following credentials were shared on Telegram, channel id: 1234567890, on 2025-04-01. They were extracted from a file named \"Example Leak Bundle.zip\" with a size of 442.0 MB.",
                "luminarthreatscore": 71,
                "luminarcollectiondate": "2025-04-02T19:01:00.498Z",
                "comment": "related-to - incident: Example_Leak_Bundle.zip",
                "incident-Value": "Example_Leak_Bundle.zip",
                "incident-stixid": "incident--4daf4333-8684-5158-82ba-8fc11a88fb93",
                "incident-description": "The following credentials were shared on Telegram, channel id: 1234567890, on 2025-04-01. They were extracted from a file named \"Example Leak Bundle.zip\" with a size of 442.0 MB.",
                "incident-luminarcollectiondate": "2025-04-02T19:01:00.498Z",
                "incident-luminarthreatscore": "71",
                "incident-relationship": "related-to"
            }
        ]
    }
}
```

#### Human Readable Output

>### Luminar Leaked Record
>
>|Type|Value|Occurred|Reported By|Tags|Category|Account Type|Username|Display Name|Email Address|Luminar Leaked Credential|Luminar Leak Source|Luminar Leak URL|Luminar Monitoring Plan Terms|Luminar Credential Is Fresh|Creation Date|Updated Date|Luminar Incident Name|Luminar Incident Description|Luminar Threat Score|Luminar Collection Date|Comment|Incident - Value|Incident - Description|Incident - Luminar Collection Date|Incident - Luminar Threat Score|Incident - Relationship|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Account | john.doe@example.com | 2025-04-01T00:00:00.000Z | Luminar | LEAKED CREDENTIAL,<br>Incident: Example_Leak_Bundle.zip | LEAKED CREDENTIAL | LEAKED CREDENTIAL | john.doe@example.com | john.doe@example.com | john.doe@example.com | ******** | telegram | www.example.com/register | example.com | false | 2025-04-01T00:00:00.000Z | 2026-09-09T04:19:40.838Z | Example_Leak_Bundle.zip | The following credentials were shared on Telegram, channel id: 1234567890, on 2025-04-01. They were extracted from a file named "Example Leak Bundle.zip" with a size of 442.0 MB. | 71 | 2025-04-02T19:01:00.498Z | related-to - incident: Example_Leak_Bundle.zip | Example_Leak_Bundle.zip | The following credentials were shared on Telegram, channel id: 1234567890, on 2025-04-01. They were extracted from a file named "Example Leak Bundle.zip" with a size of 442.0 MB. | 2025-04-02T19:01:00.498Z | 71 | related-to |
>
>**5 indicators saved to TIM.**

### luminar-v3-reset-fetch-indicators

***
Resets your fetch history.

#### Base Command

`luminar-v3-reset-fetch-indicators`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example

```!luminar-v3-reset-fetch-indicators```

#### Human Readable Output

>Fetch history deleted successfully

## Known Limitations

- The get-* commands fetch and persist the full collection (bounded only by the `from_date` argument) before rendering the table. The `limit` argument only limits the number of displayed rows; all fetched indicators are saved to TIM.
- For large `from_date` ranges, run the commands with a higher execution timeout, e.g., `!luminar-v3-get-indicators from_date="30 days" execution-timeout=3600`. For scheduled fetches, increase the `feedIntegrationScript.timeout` server configuration.
- Leaked credentials are masked (`********`) on Account indicators by default. Enable the **Include Leaked Credentials** parameter to store the plaintext value.

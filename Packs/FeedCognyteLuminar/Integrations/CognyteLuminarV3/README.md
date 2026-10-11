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
| Indicator Reputation | The reputation to apply to indicators fetched from this integration instance. | False |
| Source Reliability | The reliability of the source providing the intelligence data. | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval | The interval \(in minutes\) at which the feed fetches indicators. | False |
| Tags | A comma-separated list of tags to apply to indicators fetched from the feed. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
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

```!luminar-v3-get-indicators limit="3" from_date="7 days"```

#### Context Example

```json
{
    "LuminarV3": {
        "Indicators": [
            {
                "Type": "IP",
                "Value": "200.41.233.229",
                "Occurred": "2026-01-01T00:00:00.000000Z",
                "stixid": "indicator--8aa5f19e-1111-4aaa-bbbb-ccccddddeeee",
                "confidence": "High",
                "luminarscore": 65,
                "malwarefamily": "Lumma",
                "actor": "Example Threat Actor",
                "tags": "feed_tag"
            }
        ]
    }
}
```

#### Human Readable Output

>### Luminar Indicators
>
>|Type|Value|Occurred|confidence|luminarscore|malwarefamily|actor|
>|---|---|---|---|---|---|---|
>| IP | 200.41.233.229 | 2026-01-01T00:00:00.000000Z | High | 65 | Lumma | Example Threat Actor |
>
>**12 indicators saved to TIM.**

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

```!luminar-v3-get-leaked-records limit="3" from_date="2026-01-01T00:00:00Z"```

#### Context Example

```json
{
    "LuminarV3": {
        "LeakedCredentials": [
            {
                "Type": "Account",
                "Value": "john.doe@example.com",
                "Occurred": "2026-01-01T00:00:00.000000Z",
                "stixid": "user-account--1bb2cc33-4444-4ccc-dddd-eeeeffff0000",
                "accounttype": "LEAKED CREDENTIAL",
                "username": "john.doe@example.com",
                "emailaddress": "john.doe@example.com",
                "luminarleakedcredential": "P@ssw0rd!123",
                "luminarleaksource": "stealer_log",
                "luminarincidentname": "Example_Leak_Bundle.zip",
                "luminarthreatscore": 71,
                "luminarcollectiondate": "2026-01-01T00:00:00.000000Z",
                "tags": "LEAKED CREDENTIAL, Incident: Example_Leak_Bundle.zip"
            }
        ]
    }
}
```

#### Human Readable Output

>### Luminar Leaked Record
>
>|Type|Value|accounttype|username|luminarincidentname|luminarthreatscore|incident-name|
>|---|---|---|---|---|---|---|
>| Account | john.doe@example.com | LEAKED CREDENTIAL | john.doe@example.com | Example_Leak_Bundle.zip | 71 | Example_Leak_Bundle.zip |
>
>**42 indicators saved to TIM.**

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

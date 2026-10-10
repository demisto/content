Cognyte is a global leader in security analytics software that empowers governments and enterprises with Actionable
Intelligence for a safer world. Our open software fuses, analyzes and visualizes disparate data sets at scale to help
security organizations find the needles in the haystacks. Over 1,000 government and enterprise customers in more than
100 countries rely on Cognyte’s solutions to accelerate security investigations and connect the dots to successfully
identify, neutralize, and prevent threats to national security, business continuity and cyber security.

Luminar is an asset-based cybersecurity intelligence platform that empowers enterprise organizations to build and
maintain a proactive threat intelligence operation that enables to anticipate and mitigate cyber threats, reduce risk
and enhance security resilience.

This connector fetches intelligence-based IOC data and customer-related leaked records identified by Luminar,
using the Luminar TAXII 2.1 external API (STIX 2.1 objects). It always fetches the `IOCs` and `Leaked Records`
TAXII collections.

## Configure Cognyte Luminar V3 Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Luminar Base URL | Luminar Base URL | True |
| Luminar API Account ID | Luminar API Account ID (TAXII realm name) | True |
| Luminar API Client ID | Luminar API Client ID | True |
| Luminar API Client Secret | Luminar API Secret | True |
| First Fetch Time | First fetch time range or date for incremental fetching (e.g. "7 days", "2026-01-01T00:00:00Z"). On the first fetch, indicators added to the collections after this time are ingested. | False |
| Trust any certificate (not secure) | Trust any certificate \(not secure\) | False |
| Use system proxy settings | Use system proxy settings | False |
| Fetch indicators | Fetch indicators | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Feed Expiration Policy | Feed Expiration Policy | False |
| Feed Fetch Interval | Feed Fetch Interval | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

Note: the get-* commands fetch and persist the full collection (bounded only
by `from_date`), so a large time range can exceed the default Docker timeout.
Run them with the `execution-timeout` argument (seconds), e.g.
`!get-luminar-indicators from_date="30 days" execution-timeout=3600`. If
`fetch-indicators` itself times out on a large collection, raise the
`feedIntegrationScript.timeout` server configuration.

### get-luminar-indicators

***
Gets Luminar indicators from the `IOCs` collection.

#### Base Command

`get-luminar-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional |
| from_date | Only return objects added to the collection after this date (used as the TAXII "added_after" filter). Accepts a date range (e.g. "7 days") or an ISO date (e.g. "2026-01-01T00:00:00Z"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
All mapped indicator fields are returned in context. The most common paths are:

| LuminarV3.Indicators.Type | String | The indicator type. |
| LuminarV3.Indicators.Value | String | The indicator value. |
| LuminarV3.Indicators.Occurred | Date | The date the indicator occurred. |
| LuminarV3.Indicators.stixid | String | The STIX ID of the indicator object. |
| LuminarV3.Indicators.tags | Unknown | The indicator tags. |
| LuminarV3.Indicators.luminarscore | Number | The Luminar score of the indicator. |
| LuminarV3.Indicators.description | String | The indicator description. |
| LuminarV3.Indicators.confidence | String | The indicator confidence. |
| LuminarV3.Indicators.malwarefamily | Unknown | The malware family associated with the indicator. |
| LuminarV3.Indicators.actor | Unknown | The threat actors associated with the indicator. |

Fields of STIX objects related to each indicator are appended as additional
columns named `<stix-type>-<field>` (e.g. `malware-Value`, `malware-aliases`,
`threat-actor-Type`, `software-version`). When several objects of the same type
are related, their values are comma-separated (e.g. `malware-Value: Emotet, Trickbot`).

#### Command example

```!get-luminar-indicators limit="3" from_date="7 days"```

### luminar-v3-get-leaked-records

***
Gets Luminar leaked records (leaked credentials) from the `Leaked Records` collection.

#### Base Command

`luminar-v3-get-leaked-records`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of leaked records to return. Default is 50. | Optional |
| from_date | Only return objects added to the collection after this date (used as the TAXII "added_after" filter). Accepts a date range (e.g. "7 days") or an ISO date (e.g. "2026-01-01T00:00:00Z"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
All mapped record fields are returned in context. The most common paths are:

| LuminarV3.LeakedCredentials.Type | String | The indicator type (Account). |
| LuminarV3.LeakedCredentials.Value | String | The account login of the leaked credential. |
| LuminarV3.LeakedCredentials.Occurred | Date | The date the record occurred. |
| LuminarV3.LeakedCredentials.stixid | String | The STIX ID of the user-account object. |
| LuminarV3.LeakedCredentials.accounttype | String | The account type (LEAKED CREDENTIAL). |
| LuminarV3.LeakedCredentials.username | String | The account login. |
| LuminarV3.LeakedCredentials.emailaddress | String | The email address associated with the leaked account. |
| LuminarV3.LeakedCredentials.luminarleakedcredential | String | The leaked credential. |
| LuminarV3.LeakedCredentials.luminarleaksource | String | The source where the credential was leaked. |
| LuminarV3.LeakedCredentials.luminarleakurl | String | The URL associated with the leaked credential. |
| LuminarV3.LeakedCredentials.luminarincidentname | String | The name of the related Luminar incident. |
| LuminarV3.LeakedCredentials.luminarincidentdescription | String | The description of the related Luminar incident. |
| LuminarV3.LeakedCredentials.luminarthreatscore | Number | The threat score of the related Luminar incident. |
| LuminarV3.LeakedCredentials.luminarcomputername | String | The computer name recorded on the related Luminar incident. |
| LuminarV3.LeakedCredentials.luminarcollectiondate | Date | The date the record was collected by Luminar. |
| LuminarV3.LeakedCredentials.tags | Unknown | The record tags. |

Fields of STIX objects related to each record are appended as additional
columns named `<stix-type>-<field>` (e.g. `incident-Value`,
`incident-description`, `incident-luminarthreatscore`). For account records
one extra hop is taken through the related `incident`, so the row also shows
the other objects inside that leak bundle (e.g. `malware-Value`,
`ipv4-addr-Value`).

#### Command example

```!luminar-v3-get-leaked-records limit="3" from_date="2026-01-01T00:00:00Z"```

### luminar-v3-reset-fetch-indicators

***
WARNING: This command will reset your fetch history.

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

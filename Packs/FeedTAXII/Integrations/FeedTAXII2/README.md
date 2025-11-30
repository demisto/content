Ingest indicator feeds from TAXII 2.0 and 2.1 servers.

## Configure TAXII 2 Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name |  | True |
| Discovery Service URL (e.g. https://example.net/taxii) |  | True |
| Username / API Key |  | False |
| Password |  | False |
| API Root to Use | The API root to use (for example default or public). If left empty, the server default API root is used. If the server has no default root, the first available API root is used instead. | False |
| Collection Name To Fetch Indicators From | Indicators will be fetched from this collection. Run "taxii2-get-collections" command to get a valid value. If left empty, the instance will try to fetch from all the collections in the given discovery service. | False |
| Certificate File as Text | Add a certificate file as text to connect to the TAXII server. | False |
| Key File as Text | Add a key file as text to connect to the TAXII server | False |
| Run on Single engine |  | False |
| Trust any certificate (not secure) | Located under Advanced Settings. | False |
| Use system proxy settings | Located under Advanced Settings. | False |
| Log Level | Debug/Verbose logging is recommended only during troubleshooting. Logging can affect integration performance. Recommended usage is to turn logging on during setup and troubleshooting, and then turn it off in production. These settings only affect the integration log. The server log is not affected. | False |
| Do not use in CLI by default |  | False |
| Fetch indicators |  | False |
| Classifier | Determines the type of incident that is created for events ingested from this integration instance. | False |
| Mapper (incoming) | Determines how event fields are mapped to the Cortex XSOAR incident fields. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Max Indicators Per Fetch (disabled for Full Feed Fetch) | The maximum number of indicators that can be fetched per fetch. If this field is left empty, there will be no limit on the number of indicators fetched. | False |
| First Fetch Time | The time interval for the first fetch \(retroactive\). &amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt; of type minute/hour/day/year. For example, 1 minute, 12 hour | False |
| STIX Objects To Fetch | Which STIX objects to fetch from the TAXII server. If left empty, all available object types will be fetched. | False |
| Max STIX Objects Per Poll | Set the number of stix object that will be requested with each TAXII poll \(http request\). A single fetch is made of several taxii polls. Changing this setting can help speed up fetches, or fix issues on slower networks. Please note server restrictions may apply, overriding and limiting the "requested limit". | False |
| Enrichment Excluded | Select this option to exclude the fetched indicators from the enrichment process. | False |
| Indicator Expiration Method |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Incremental Feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. As the determination if the indicator is new or modified happens on the 3rd-party vendor's side, and only indicators that are new or modified are sent to Cortex XSOAR, all indicators coming from these feeds are labeled new or modified. | False |
| Full Feed Fetch | When enabled, fetch-indicators will try to fetch the entire feed for every fetch. When disabled, fetch-indicators will try to fetch just the latest entries \(since the last fetch\). | False |
| Complex Observation Mode | Choose how to handle complex observations. Two or more observation expressions can be combined using a complex observation operator such as "AND", "OR". e.g. \`\[ IP = 'b' \] AND \[ URL = 'd' \]\` | False |
| Update custom fields | Choose whether to import the XSOAR custom fields. Note: this might overwrite the data pulled from other sources. | False |
| Tags | Supports CSV values. | False |

### Using API token authentication

To use the integration with an API token you first need to change the `Username / API Key (see '?')` field to `_api_token_key`. You can then enter the API Token into the `Password` field - this value will be used as an API key.

### Using a custom authentication header

If the TAXII 2 server you are trying to connect to requires a custom authentication header, you first need to change the `Username / API Key (see '?')` field to `_header:` and the custom header name, e.g. `_header:custom_auth`. You can then enter the custom auth header value into the `Password` field - this value will be used as a custom auth header.

### Complex Observation Mode consideration

You can combine two or more observation expressions using a complex observation operator such as "AND", "OR", and "FOLLOWEDBY", for example `[ IP = 'b' ] AND [ URL = 'd' ]`. These relationships are not represented in CORTEX XSOAR TIM indicators. You can create them while ignoring these relations, or you can ignore these expressions. If you choose to ignore these expressions, then no indicator will be created for complex observations.

### Enrichment Excluded consideration

Setting the **Traffic Light Protocol Color** to red automatically excludes enrichment, even if **Enrichment Excluded** is unchecked.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### taxii2-get-indicators

***
Allows you to test your feed and to make sure you can fetch indicators successfuly.

#### Base Command

`taxii2-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| raw | Will return only the rawJSON of the indicator object. | Optional |
| limit | Maximum number of indicators to fetch. | Optional |
| added_after | Fetch only indicators that were added to the server after the given time. Please provide a &lt;number&gt; and &lt;time unit&gt; of type minute/hour/day. For example, 1 minute, 12 hour, 24 days. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TAXII2.Indicators.type | String | Indicator type. |
| TAXII2.Indicators.value | String | Indicator value. |
| TAXII2.Indicators.rawJSON | String | Indicator rawJSON. |

#### Command Example

```!taxii2-get-indicators limit=3```

#### Human Readable Output

|value|type|
|---|---|
| coronashop.jp | Domain |
| e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e | File |
| 2014\[.\]zzux\[.\]com | Domain |

### taxii2-get-collections

***
Gets the list of collections from the discovery service.

#### Base Command

`taxii2-get-collections`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TAXII2.Collections.ID | String | Collection ID. |
| TAXII2.Collections.Name | String | Collection Name. |

#### Command Example

```!taxii2-get-collections```

#### Human Readable Output

|Name|ID|
|---|---|
| Phish Tank | 107 |
| Abuse.ch Ransomware IPs | 135 |
| Abuse.ch Ransomware Domains | 136 |
| DShield Scanning IPs | 150 |
| Malware Domain List - Hotlist | 200 |
| Blutmagie TOR Nodes | 209 |
| Emerging Threats C&C Server | 31 |
| DT COVID-19 | 313 |
| Lehigh Malwaredomains | 33 |
| CyberCrime | 41 |
| Emerging Threats - Compromised | 68 |

### taxii2-reset-fetch-indicators

***
WARNING: This command will reset your fetch history.

#### Base Command

`taxii2-reset-fetch-indicators`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!taxii2-reset-fetch-indicators```

#### Human Readable Output

Fetch was reset successfully. Your next indicator fetch will collect indicators from the configured "First Fetch Time"

### Troubleshooting

When the feed is set to "Incremental Feed", we recommend specifying a value for the **Max Indicators Per Fetch** parameter to prevent potential timeout issues.

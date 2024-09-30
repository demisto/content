Ingest indicator feeds from TAXII 2.0 and 2.1 servers.

## Configure TAXII 2 Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Discovery Service URL (e.g. https://example.net/taxii) |  | True |
| Username / API Key |  | False |
| Password |  | False |
| Collection Name To Fetch Indicators From | Indicators will be fetched from this collection. Run "taxii2-get-collections" command to get a valid value. If left empty, the instance will try to fetch from all the collections in the given discovery service. | False |
| Incremental Feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. As the determination if the indicator is new or modified happens on the 3rd-party vendor's side, and only indicators that are new or modified are sent to Cortex XSOAR, all indicators coming from these feeds are labeled new or modified. | False |
| Full Feed Fetch | When enabled, fetch-indicators will try to fetch the entire feed for every fetch. When disabled, fetch-indicators will try to fetch just the latest entries \(since the last fetch\). | False |
| Max Indicators Per Fetch (disabled for Full Feed Fetch) | The maximum number of indicators that can be fetched per fetch. If this field is left empty, there will be no limit on the number of indicators fetched. | False |
| First Fetch Time | The time interval for the first fetch \(retroactive\). &amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt; of type minute/hour/day/year. For example, 1 minute, 12 hour | False |
| STIX Objects To Fetch |  | False |
| Certificate File as Text | Add a certificate file as text to connect to the TAXII server | False |
| Key File as Text | Add a key file as text to connect to the TAXII server | False |
| Max STIX Objects Per Poll | Set the number of stix object that will be requested with each taxii poll \(http request\). A single fetch is made of several taxii polls. Changing this setting can help speed up fetches, or fix issues on slower networks. Please note server restrictions may apply, overriding and limiting the "requested limit". | False |
| Complex Observation Mode | Choose how to handle complex observations. Two or more Observation Expressions MAY be combined using a complex observation operator such as "AND", "OR". e.g. \`\[ IP = 'b' \] AND \[ URL = 'd' \]\` | False |
| Update custom fields | Choose whether to import the XSOAR custom fields. Note: this might overwrite the data pulled from other sources. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Tags | Supports CSV values. | False |
| Default API Root to use | The Default API Root to use (e.g. default, public). If left empty, the server default API root will be used. When the server has no default root, the first available API root will be used instead. Providing an API root that can't be reached will result in an error message with all possible API roots listed. | False |


### Using API Token authentication
In order to use the integration with an API token you'll first need to change the `Username / API Key (see '?')` field to `_api_token_key`. Following this step, you can now enter the API Token into the `Password` field - this value will be used as an API key.


### Using custom authentication header
In case the TAXII 2 server you're trying to connect to requires a custom authentication header, you'll first need to change the `Username / API Key (see '?')` field to `_header:` and the custom header name, e.g. `_header:custom_auth`. Following this step, you can now enter the custom auth header value into the `Password` field - this value will be used as a custom auth header.

### Complex Observation Mode
Two or more Observation Expressions MAY be combined using a complex observation operator such as "AND", "OR", and "FOLLOWEDBY". e.g. `[ IP = 'b' ] AND [ URL = 'd' ]`. These relationships are not represented in in CORTEX XSOAR TIM indicators. You can opt to create them while ignoring these relations, or you can opt to ignore these expressions - if you chose the latter, then no indicator will be created for complex observations.


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

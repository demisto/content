Ingest indicator feeds from TAXII 2.0 and 2.1 servers.

## Configure TAXII 2 Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for TAXII 2 Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Required** |
| --- | --- |
| Fetch indicators | False |
| Indicator Reputation | False |
| Source Reliability | True |
| Traffic Light Protocol Color | False
| Feed Fetch Interval | False |
| Bypass exclusion list | False |
| Discovery Service URL \(e.g. https://example.net/taxii\) | True |
| Username / API Key / Custom Auth Header | False |
| Collection Name To Fetch Indicators From | False |
| Full Feed Fetch | False |
| Max Indicators Per Fetch \(disabled for Full Feed Fetch\) | False |
| First Fetch Time | False |
| Filter Arguments | False |
| Max STIX Objects Per Poll | False |
| Complex Observation Mode | False |
| Trust any certificate \(not secure\) | False |
| Use system proxy settings | False |
| Tags | False |

4. Click **Test** to validate the URLs, token, and connection.

### Using API Token authentication
In order to use the integration with an API token you'll first need to change the `Username / API Key (see '?')` field to `_api_token_key`. Following this step, you can now enter the API Token into the `Password` field - this value will be used as an API key.


### Using custom authentication header
In case the TAXII 2 server you're trying to connect to requires a custom authentication header, you'll first need to change the `Username / API Key (see '?')` field to `_header:` and the custom header name, e.g. `_header:custom_auth`. Following this step, you can now enter the custom auth header value into the `Password` field - this value will be used as a custom auth header.

### Complex Observation Mode
Two or more Observation Expressions MAY be combined using a complex observation operator such as "AND", "OR", and "FOLLOWEDBY". e.g. `[ IP = 'b' ] AND [ URL = 'd' ]`. These relationships are not represented in in CORTEX XSOAR TIM indicators. You can opt to create them while ignoring these relations, or you can opt to ignore these expressions - if you chose the latter, then no indicator will be created for complex observations.


## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
| filter_args | Deprecated. TAXII filter arguments. Comma-separated values e.g.: "added_after=&lt;date&gt;,revoked=true". | Optional | 


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


Deprecated. Use ***Unit42 ATOMs Feed*** instead.

Unit42 feed of published IOCs, which contains known malicious indicators.

Note: Install the MITRE ATT&CK pack if you want the feed to create MITRE ATT&CK indicators in your environment from the the STIX reports.

## Configure Unit42 Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| api_key | API Key | False |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp. | False |
| feedExpirationPolicy | The feed’s expiration policy. | False |
| feedExpirationInterval | The interval after which the feed expires. | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| feedTags | Tags | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### unit42-get-indicators
***
Retrieves a limited number of the indicators.


#### Base Command

`unit42-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
!unit42-get-indicators limit=3

#### Human Readable Output
|value|type|
|---|---|
| c1ec28bc82500bd70f95edcbdf9306746198bbc04a09793ca69bb87f2abdb839 | File |
| e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e | File |
| 2014\[.\]zzux\[.\]com | Domain |

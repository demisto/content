Mandiant Feed Integration.

## Configure Mandiant Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Feed Fetch Interval |  | False |
| Public Key |  | True |
| Secret Key |  | True |
| feedExpirationInterval | The interval after which the feed expires. | False |
| feedExpirationPolicy | The feed's expiration policy. | False |
| Mandiant indicator type | The indicators' type to fetch. Indicator type might include the following: Domains, IPs, Files and URLs. | False |
| First fetch time | The maximum value allowed is 90 days. | False |
| Server URL (e.g. https://api.intelligence.fireeye.com) |  | True |
| Maximum number of indicators per fetch |  | False |
| Tags | Supports CSV values. | False |
| Timeout | API calls timeout. | False |
| Trust any certificate (not secure) |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Retrieve indicator metadata | Retrieve additional information for each indicator. Please note that this requires additional API calls. | False |
| Create relationships | Please note that this requires additional API calls. | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### feed-mandiant-get-indicators
***
get mandiant indicators


#### Base Command

`feed-mandiant-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| update_context | update context. | Optional | 
| limit | number of indicators to fetch. | Optional | 
| indicatorMetadata | Retrieve additional data for each indicator. Possible values are: true, false. Default is false. | Optional | 
| indicatorRelationships | Create relationships. Possible values are: true, false. Default is false. | Optional | 
| type | What indicators types to fetch. Possible values are: Malware, Indicators, Actors. Default is Malware,Indicators,Actors. | Required | 


#### Context Output

There is no context output for this command.
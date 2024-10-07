Detailed feed of domains and ips classified in different categories. You need a valid authorization code from Proofpoint ET to access this feed

## Configure Proofpoint Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Authorization Code |  | True |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Indicator Type | The indicator type in the feed to fetch. Domain is referring to "https://rules.emergingthreats.net/auth_code/reputation/detailed-iprepdata.txt", IP is referring to "https://rules.emergingthreats.net/auth_code/reputation/detailed-domainrepdata.txt". | True |
| Tags | Supports CSV values. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### proofpoint-get-indicators
***
Gets indicators from the feed.


#### Base Command

`proofpoint-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return to the output. The default value is "50". Default is 50. | Optional | 
| indicator_type | The indicator type to fetch. Possible values are: all, domain, ip. Default is all. | Optional | 


#### Context Output

There is no context output for this command.
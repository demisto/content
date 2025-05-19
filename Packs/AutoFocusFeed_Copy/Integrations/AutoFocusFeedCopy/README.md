Use the AutoFocus Feeds integration to fetch indicators from AutoFocus.
## Configure AutoFocus Feed_copy in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Indicator Feed |  | True |
| API Key |  | False |
| The URL for the custom feed to fetch | Only necessary in case a Custom Feed is fetched. Can also support a CSV of Custom feed URLs. | False |
| Samples Feed Scope Type | Only necessary in case a Samples Feed is fetched. | False |
| Samples Feed Query | Relevant only for sample feeds. JSON styled AutoFocus query, an example can be found in the description \(?\) section. mandatory for Samples Feed. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Tags | Supports CSV values. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### autofocus-get-indicators

***
Gets the indicators from AutoFocus.

#### Base Command

`autofocus-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 10. | Optional | 
| offset | The index of the first indicator to fetch. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.

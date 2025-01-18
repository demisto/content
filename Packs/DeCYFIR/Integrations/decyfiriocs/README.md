DeCYFIR API's provides External Threat Landscape Management insights.
This integration was integrated and tested with version v1 of DeCYFIR Feed

## Configure DeCYFIR Indicators & Threat Intelligence Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| DeCYFIR Server URL (e.g. https://decyfir.cyfirma.com) |  | True |
| DeCYFIR API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### decyfir-get-indicators

***
Gets indicators from the feed.

#### Base Command

`decyfir-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
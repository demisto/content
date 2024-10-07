Use the ThreatFox Feed integration to fetch indicators from the feed.
This integration was integrated and tested with version 6.0.3 of ThreatFox Feed.

## Configure ThreatFox Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Fetch indicators |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Indicator Expiration Method | The method to be used to expire indicators from this feed. Default: indicatorType | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Feed Fetch Interval (in days) |  | False |
| Return IOCs with Ports | If selected, IP indicators will include a tag with the port value | False |
| Confidence Threshold |  | False |
| Create relationship | If selected, indicators will be created with relationships | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatfox-get-indicators

***
Retrieves indicators from the ThreatFox API.

#### Base Command

`threatfox-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_term | Indicator value to search for | Optional | 
| id | Indicator ID to search for. | Optional | 
| hash | Hash to search for. | Optional | 
| tag | Tag to search by. For available tag options, please refer to the API documentation- https://threatfox.abuse.ch/api/. | Optional | 
| malware | Malware to search by. For available malware options, please refer to the API documentation- https://threatfox.abuse.ch/api/. | Optional | 
| limit | Maximum indicators to search for. Available only when searching by 'malware' or 'tag'. Default is 50. Max is 1000. | Optional | 

#### Context Output

There is no context output for this command.
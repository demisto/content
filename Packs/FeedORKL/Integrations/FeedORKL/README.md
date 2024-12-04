Use the ORKL Threat Intel Feed integration to get receive threat intelligence indicators from the feed.
This integration was integrated and tested with version 1.0.0 of FeedORKL.

## Configure ORKL Threat Intel Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Create Relationships | Fetch related indicators. Default is "False". | False |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Maximum Indicators per fetch |  | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### orkl-get-reports

***
Retrieves latest Threat Reports from ORKL

#### Base Command

`orkl-get-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of Reports to return. Default is 5. | Optional | 
| order_by | Criteria to order Threat Reports. Possible values are: created_at, updated_at, file_creation_date, file_modification_date. Default is file_creation_date. | Optional | 
| order | Ordering of results. Possible values are: asc, desc. Default is desc. | Optional | 

#### Context Output

There is no context output for this command.
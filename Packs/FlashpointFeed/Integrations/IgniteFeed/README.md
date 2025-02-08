Flashpoint Ignite Feed Integration allows importing indicators of compromise that occur in the context of an event on the Flashpoint Ignite platform which contains finished intelligence reports data, data from illicit forums, marketplaces, chat services, blogs, paste sites, technical data, card shops, and vulnerabilities. The indicators of compromise are ingested as indicators on the Cortex XSOAR and displayed in the War Room using a command.
This integration was integrated and tested with API v1 of Ignite.

## Fetch Indicators
Fetching the Ignite indicators. The indicators that are created or updated after the provided "First fetch time" will be fetched in the ascending order.

If you are upgrading from a Flashpoint Feed integration, please refer to the [Migration Guide](#migration-guide) for guidance.

## Configure Flashpoint Ignite Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Server URL to connect to Ignite. | True |
| API Key | API key used for secure communication with the Ignite platform. | True |
| Types of the indicators to fetch | Supports multiple values such as url, domain. Supports comma separated values. If not specified, it fetches all the indicators. See all available types: https://www.circl.lu/doc/misp/categories-and-types/#types. | False |
| First fetch time | Backfill indicators by providing date or relative timestamp. \(Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc\) | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| feedIncremental | To indicate to the Cortex XSOAR server that a feed is incremental. Generally feeds that fetch based on a time range. For example, a daily feed which provides new indicators for the last day or a feed which is immutable and provides indicators from a search date onwards. | False |
| Create relationships | Create relationships between indicators as part of Enrichment. | False |
| Default Indicator Mapping | When selected, all the incoming indicators will map to the Flashpoint Indicator. | False |
| Trust any certificate (not secure) | Indicates whether to allow connections without verifying SSL certificate's validity. | False |
| Use system proxy settings | Indicates whether to use XSOAR's system proxy settings to connect to the API. | False |


## Troubleshooting

### Error: The maximum indicators to fetch for the given first fetch can not exceed 10,000

- The maximum number of indicators that can be fetched using the first fetch time is limited to 10,000 by the API.
- To resolve this issue, you can reduce the first fetch time to a shorter time period, ensuring that the total number of indicators fetched during the specified time falls within the 10,000 limit.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### flashpoint-ignite-get-indicators

***
Retrieves indicators from the Ignite API. It displays the content of the fetch-indicators command.

#### Base Command

`flashpoint-ignite-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of result objects to return. Maximum allowed limit is 1000. Default is 10. | Optional | 
| updated_since | Only retrieve values after the given timestamp. This parameter operates on the timestamp when an IOC was last updated, i.e. enriched with more metadata. When the user wants the most recent IOCs shared in the past week, the freshest data, we recommend using this parameter.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc. Default is 3 days. | Optional | 
| types | Search by Attribute types. Can have multiple terms. See all available types: https://www.circl.lu/doc/misp/categories-and-types/#types. Possible values are: IP, Domain, URL, Email, File. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!flashpoint-ignite-get-indicators limit=2 types=URL updated_since="3 days"```
#### Human Readable Output

>### Indicator(s)
>|FPID|Indicator Type|Indicator Value|Category|Event Name|Event Tags|Created Timestamp (UTC)|First Observed Date|
>|---|---|---|---|---|---|---|---|
>| [dummy_fpid1](https://app.flashpoint.io.com/cti/malware/iocs?query=1000-0000-0000-0000&sort_date=All%20Time) | url | https://dummy_url1.com/attachments/1234/1234/dummy_file1.exe | Payload delivery | Analysis: dummy_event1 "dummy_value1" [2024-04-13 17:10:40] | analysis_id:12345,<br/>event:analysis,<br/>malware:dummy_event1,<br/>misp-galaxy:mitre-enterprise-attack-attack-pattern="Software Packing - T1045",<br/>os:windows | 2024-04-13T18:01:24Z | 2024-04-13T18:02:08+00:00 |
>| [dummy_fpid2](https://app.flashpoint.io.com/cti/malware/iocs?query=1000-0000-0000-0001&sort_date=All%20Time) | url | http://dummy_url2.com/dummy_file2.exe | Payload delivery | Analysis: dummy_event1 "dummy_value2" [2024-04-13 14:00:26] | analysis_id:56789,<br/>event:analysis,<br/>file_type:exe,<br/>malware:remcos,<br/>misp-galaxy:mitre-enterprise-attack-attack-pattern="Code Signing - T1116" | 2024-04-13T14:10:50Z | 2024-04-13T14:11:08+00:00 |

## Migration Guide

**Note:**  
For **fetching indicator**, set the **First Fetch** time to the previous integration's **Feed Fetch Interval** time. This might create duplicate indicators, but it will ensure that no indicators is lost.

### Migrated Commands

Some of the previous integration's commands have been migrated to new commands. Below is the table showing the commands that have been migrated to the new ones.

| **Flashpoint Command** | **Migrated Ignite Command** |
| --- | --- |
| flashpoint-get-indicators | flashpoint-ignite-get-indicators |
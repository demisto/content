Deprecated. Use Flashpoint Ignite Feed instead.
This integration was integrated and tested with version 4.0.0 of FlashpointFeed

## Fetch Indicators
Fetching the Flashpoint indicators. The indicators that are created or updated after the provided first fetch time interval will be fetched in the ascending order. 

## Configure FlashpointFeed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Server URL to connect to Flashpoint. | True |
| API Key |  | True |
| Types of the indicators to fetch | Supports multiple values such as url, domain, ip-src. Supports comma separated values. If not specified, it fetches all the indicators. See all available types: https://www.circl.lu/doc/misp/categories-and-types/#types. | False |
| First fetch time interval | Backfill indicators by providing date or relative timestamp.  \(Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc\) | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| feedExpirationPolicy | | False |
| feedExpirationInterval | | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| feedIncremental | To indicate to the Cortex XSOAR server that a feed is incremental. Generally feeds that fetch based on a time range. For example, a daily feed which provides new indicators for the last day or a feed which is immutable and provides indicators from a search date onwards. | False |
| Create relationships | Create relationships between indicators as part of Enrichment. | False |
| Default Indicator Mapping | When selected, all the incoming indicators will map to the Flashpoint Indicator. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### flashpoint-get-indicators
***
Retrieves indicators from the Flashpoint API. It displays the content of the fetch-indicators command.


#### Base Command

`flashpoint-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of result objects to return. Maximum allowed limit is 1000. Default is 10. | Optional | 
| updated_since | Only retrieve values after the given timestamp. This parameter operates on the timestamp when an IOC was last updated, i.e. enriched with more metadata. When you want the most recent IOCs shared in the past week, the freshest data, we recommend using this parameter. Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc. Default is 3 days. | Optional | 
| types | Search by Attribute types. Can have multiple terms. Example: url, domain, ip-src. See all available types: https://www.circl.lu/doc/misp/categories-and-types/#types. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!flashpoint-get-indicators limit=10 types=url updated_since="3 days"```

#### Human Readable Output

>### Indicator(s)
>|FPID|Indicator Type|Indicator Value|Category|Event Name|Event Tags|Created Timestamp (UTC)|First Observed Date|
>|---|---|---|---|---|---|---|---|
>| [dummy_fpid1](https://fp.tools/api/v4/indicators/attribute/dummy_fpid1) | url | https://dummy_url1.com/attachments/1234/1234/dummy_file1.exe | Payload delivery | Analysis: dummy_event1 "dummy_value1" [2021-07-06 20:11:11] | analysis_id:12345,<br/>event:analysis,<br/>malware:dummy_event1,<br/>misp-galaxy:mitre-enterprise-attack-attack-pattern="Software Packing - T1045",<br/>os:windows,<br/>source:virustotal,<br/>type:trojan | 2021-07-06T22:31:24Z | 2021-07-06T22:31:44+00:00 |
>| [dummy_fpid2](https://fp.tools/api/v4/indicators/attribute/dummy_fpid2) | url | http://dummy_url2.com/dummy_file2.exe | Payload delivery | Analysis: dummy_event1 "dummy_value2" [2021-07-06 21:17:56] | analysis_id:56789,<br/>event:analysis,<br/>file_type:exe,<br/>malware:remcos,<br/>misp-galaxy:mitre-enterprise-attack-attack-pattern="Code Signing - T1116",<br/>misp-galaxy:mitre-enterprise-attack-attack-pattern="Disabling Security Tools - T1089",<br/>misp-galaxy:mitre-enterprise-attack-attack-pattern="Registry Run Keys / Start Folder - T1060",<br/>misp-galaxy:mitre-enterprise-attack-attack-pattern="Software Packing - T1045",<br/>misp-galaxy:mitre-enterprise-attack-attack-pattern="Timestomp - T1099",<br/>misp-galaxy:mitre-enterprise-attack-course-of-action="Process Injection Mitigation - T1055",<br/>misp-galaxy:mitre-mobile-attack-attack-pattern="Lockscreen Bypass - MOB-T1064",<br/>os:windows,<br/>source:virustotal | 2021-07-06T22:33:18Z | 2021-07-06T22:34:02+00:00 |
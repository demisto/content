This playbook queries Strata Logging Service (SLS) for file indicators, including SHA256 hashes, file names, and file types.

Note that multiple search values should be separated by commas only (without spaces or any special characters).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Strata Logging Service

### Scripts
* SetAndHandleEmpty

### Commands
* cdl-query-file-data
* cdl-query-threat-logs

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SHA256 | A single or multiple SHA256 file hashes to search for within Strata Logging Service.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| Filename | A single or multiple file names to search for within Strata Logging Service.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| FileType | A single or multiple file types to search for within Strata Logging Service.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| time_range | An alternative to the 'start_time' and 'end_time' inputs that indicates the timeframe for the search, e.g. 1 week, 1 day, 30 minutes.<br/><br/>When the time_range input is specified, the 'start_time' and 'end_time' inputs should not be used. |  | Optional |
| start_time | Specify the query start time at which to perform a search within Strata Logging Service.<br/><br/>For example, start_time="2018-04-26 00:00:00" |  | Optional |
| end_time | Specify the query end time at which to perform a search within Strata Logging Service.<br/><br/>For example, end_time="2018-04-26 00:00:00" |  | Optional |
| limit | The maximum number of logs to return. <br/>Default is 10. |  | Optional |
| fields | Select the fields you wish to be included in the query results. <br/>Selection can be "all" \(same as \*\) or a comma-separated list of specific fields in the table.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| FirewallAction | Filter network traffic logs that should be retrieved from Strata Logging Service based on firewall action.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| rule_matched | Filter network traffic logs to be retrieved from Strata Logging Service based on security policy rule names that the network traffic matches.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CDL.HuntingResults | Event log objects and fields that were retrieved from Strata Logging Service \(SLS\). | string |
| CDL.HuntingResults.TimeGenerated | Time when the log was generated on the firewall's data plane. | number |
| CDL.HuntingResults.LogTime | Time the log was received in Strata Logging Service. | number |
| CDL.HuntingResults.IngestionTime | Ingestion time of the log. | number |
| CDL.HuntingResults.App | Application associated with the network traffic. | string |
| CDL.HuntingResults.AppCategory | Identifies the high-level family of the application. | string |
| CDL.HuntingResults.RiskOfApp | Indicates how risky the application is from a network security perspective. | string |
| CDL.HuntingResults.CharacteristicOfApp | Identifies the behavioral characteristic of the application associated with the network traffic. | string |
| CDL.HuntingResults.SanctionedStateOfApp | Indicates whether the application has been flagged as sanctioned by the firewall administrator. | string |
| CDL.HuntingResults.SessionID | Identifies the firewall's internal identifier for a specific network session. | string |
| CDL.HuntingResults.Action | Identifies the action that the firewall took for the network traffic. | string |
| CDL.HuntingResults.Protocol | IP protocol associated with the session. | string |
| CDL.HuntingResults.SourcePort | Source port utilized by the session. | number |
| CDL.HuntingResults.DestinationPort | Network traffic's destination port. If this value is 0, then the app is using its standard port. | number |
| CDL.HuntingResults.DestinationIP | Original destination IP address. | string |
| CDL.HuntingResults.SourceIP | Original source IP address. | string |
| CDL.HuntingResults.Users | Source/Destination user. If neither is available, source_ip is used. | string |
| CDL.HuntingResults.IsPhishing | Indicates whether enterprise credentials were submitted by an end user. | string |
| CDL.HuntingResults.SourceLocation | Source country or internal region for private addresses. | string |
| CDL.HuntingResults.DestinationLocation | Destination country or internal region for private addresses. | string |
| CDL.HuntingResults.RuleMatched | Unique identifier for the security policy rule that the network traffic matched. | string |
| CDL.HuntingResults.ThreatCategory | Threat category of the detected threat. | string |
| CDL.HuntingResults.LogSourceName | Name of the source of the log. | string |
| CDL.HuntingResults.Direction | Indicates the direction of the attack. | string |
| CDL.HuntingResults.FileName | The name of the file that is blocked. | string |
| CDL.HuntingResults.FileSHA256 | The binary hash \(SHA256\) of the file. | string |
| CDL.HuntingResults.IsURLDenied | Indicates whether the session was denied due to a URL filtering rule. | string |
| CDL.HuntingResults.URLDomain | The name of the internet domain that was visited in this session. | string |
| CDL.HuntingResults.URLCategory | The URL category. | string |
| CDL.HuntingResults.SourceDeviceHost | Hostname of the device from which the session originated. | string |
| CDL.HuntingResults.DestDeviceHost | Hostname of the device session destination. | string |

## Playbook Image
---
![Strata Logging Service - File Indicators Hunting](../doc_files/Cortex_Data_Lake_-_File_Indicators_Hunting.png)
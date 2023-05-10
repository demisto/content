This playbook queries Rapid7 InsightIDR SIEM for execution flow indicators, including registry values, registry keys, registry hives, commands, processes name, and applications. 

Note that multiple search values should be separated by commas only (without spaces or any special characters).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Rapid7 InsightIDR

### Scripts
* SetAndHandleEmpty
* IsIntegrationAvailable
* LoadJSON

### Commands
* rapid7-insight-idr-query-log-set

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Application | A single or multiple application names to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRAppField | The name of the fields, in Rapid7 InsightIDR, in which to find the application names. |  | Optional |
| RegistryValue | A single or multiple registry values to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRRegistryValueField | The name of the fields, in Rapid7 InsightIDR, in which to find the registry values. |  | Optional |
| RegistryKey | A single or multiple registry keys to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRRegistryKeyField | The name of the fields, in Rapid7 InsightIDR, in which to find the registry keys. |  | Optional |
| RegistryHives | Only relevant for hunting on Windows hosts.<br/>A single or multiple registry hives to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRRegistryHivesField | The name of the fields, in Rapid7 InsightIDR, in which to find the registry hives. |  | Optional |
| CommandLine | A single or multiple command to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRCommandLineField | The name of the fields, in Rapid7 InsightIDR, in which to find the command's lines. |  | Optional |
| ProcessName | A single or multiple process names to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRProcessNameField | The name of the fields, in Rapid7 InsightIDR, in which to find the process names. |  | Optional |
| LogSetId | An identifier for a Rapid7 InsightIDR log set to query. |  | Required |
| time_range | Specify the timeframe in which the Rapid7 InsightIDR logs will be searched. Most start with 'last' \(e.g., last 2 months, last 10 minutes\).<br/>The 'start_time' and 'end_time' inputs should not be used if the time_range input is specified.<br/><br/>Supported time units \(case insensitive\):<br/>min\(s\) or minute\(s\)<br/>hr\(s\) or hour\(s\)<br/>day\(s\)<br/>week\(s\)<br/>month\(s\)<br/>year\(s\) |  | Optional |
| logs_per_page | Specify the maximum number of log entries to return per page, up to 500 \(the maximum allowed\). By default, 50 is set. |  | Optional |
| sequence_number | The earliest sequence number of a log entry to start searching.<br/><br/>If this query parameter is included, the query results will additionally include all log entries received in the 'start_time' millisecond which have sequence numbers larger than the one specified.<br/><br/>Sequence numbers are identifiers used to distinguish between log entries received in the same millisecond. If a log entry was split up into several log entries during ingestion, then those chunks are ordered by sequence number. |  | Optional |
| start_time | Specify the query start time at which the Rapid7 InsightIDR logs will be searched, as a UNIX timestamp in milliseconds.<br/><br/>For example, if you wish to begin searching 1 week ago, the UNIX timestamp value is 604800. |  | Optional |
| end_time | Specify the query end time at which the Rapid7 InsightIDR logs will be searched, as a UNIX timestamp in milliseconds.<br/><br/>For example, to end searching a day ago, the UNIX timestamp value would be 86400. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Rapid7InsightIDR.HuntingResults | Events log objects containing relevant fields. | string |

## Playbook Image
---
![Rapid7 InsightIDR - Execution Flow Indicators Hunting](../doc_files/Rapid7_InsightIDR_-_Execution_Flow_Indicators_Hunting.png)
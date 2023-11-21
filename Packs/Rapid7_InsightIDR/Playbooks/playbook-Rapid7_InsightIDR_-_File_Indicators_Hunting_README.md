This playbook queries Rapid7 InsightIDR SIEM for file indicators, including MD5 hashes, SHA256 hashes, SHA1 hashes, file names, file types, and file paths.

Note that multiple search values should be separated by commas only (without spaces or any special characters).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Rapid7 InsightIDR

### Scripts
* IsIntegrationAvailable
* LoadJSON
* SetAndHandleEmpty

### Commands
* rapid7-insight-idr-query-log-set

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileType | A single or multiple file types to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRFileTypeField | The name of the fields, in Rapid7 InsightIDR, in which to find the file types. |  | Optional |
| FileName | A single or multiple file names to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRFileNameField | The name of the fields, in Rapid7 InsightIDR, in which to find the file names. |  | Optional |
| MD5 | A single or multiple MD5 file hashes to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRMD5Field | The name of the fields, in Rapid7 InsightIDR, in which to find the MD5 hashes. |  | Optional |
| SHA256 | A single or multiple SHA256 file hashes to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRSHA256Field | The name of the fields, in Rapid7 InsightIDR, in which to find the SHA256 hashes. |  | Optional |
| SHA1 | A single or multiple SHA1 file hashes to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRSHA1Field | The name of the fields, in Rapid7 InsightIDR, in which to find the SHA1 hashes. |  | Optional |
| FilePath | A single or multiple file paths to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRFilePathField | The name of the fields, in Rapid7 InsightIDR, in which to find the file paths. |  | Optional |
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
![Rapid7 InsightIDR - File Indicators Hunting](../doc_files/Rapid7_InsightIDR_-_File_Indicators_Hunting.png)
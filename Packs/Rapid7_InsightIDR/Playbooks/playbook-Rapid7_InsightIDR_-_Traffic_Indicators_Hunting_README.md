This playbook queries Rapid7 InsightIDR SIEM for traffic indicators, including URLs, domains, ports, IP addresses, IP ranges (CIDR), email addresses, and geolocations. 

Note that multiple search values should be separated by commas only (without spaces or any special characters).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Rapid7 InsightIDR

### Scripts
* LoadJSON
* IsIntegrationAvailable
* SetAndHandleEmpty

### Commands
* rapid7-insight-idr-query-log-set

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IPAddress | A single or multiple IP addresses to search for within Rapid7 InsightIDR logs. Used for both source and destination IP addresses.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRdstIPField | The name of the fields, in Rapid7 InsightIDR, in which to find the destination IPs. |  | Optional |
| InsightIDRsrcIPField | The name of the fields, in Rapid7 InsightIDR, in which to find the source IPs. |  | Optional |
| PortNumber | A single or multiple IP addresses to search for within Rapid7 InsightIDR logs. Used for both source and destination ports.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRsrcPortField | The name of the fields, in Rapid7 InsightIDR, in which to find the source ports. |  | Optional |
| InsightIDRdstPortField | The name of the fields, in Rapid7 InsightIDR, in which to find the destination ports. |  | Optional |
| Geolocation | A single or multiple country names or codes to search for within Rapid7 InsightIDR logs. Used for both source and destination geolocations.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRsrcGeolocationField | The name of the fields, in Rapid7 InsightIDR, in which to find the source geolocations. |  | Optional |
| InsightIDRSdstGeolocationField | The name of the fields, in Rapid7 InsightIDR, in which to find the destination geolocations. |  | Optional |
| URLDomain | Single or multiple URLs and/or domains to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRURLDomainField | The name of the fields, in Rapid7 InsightIDR, in which to find the URLs or domains. |  | Optional |
| EmailAddress | A single or multiple email addresses to search for within Rapid7 InsightIDR logs. Used for both sender and recipient email addresses.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| InsightIDRSenderField | The name of the fields, in Rapid7 InsightIDR, in which to find the sender's email addresses. |  | Optional |
| InsightIDRRecipientField | The name of the fields, in Rapid7 InsightIDR, in which to find the recipient's email addresses. |  | Optional |
| CIDR | A single or multiple IP ranges to search for within Rapid7 InsightIDR logs.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
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
![Rapid7 InsightIDR - Traffic Indicators Hunting](../doc_files/Rapid7_InsightIDR_-_Traffic_Indicators_Hunting.png)
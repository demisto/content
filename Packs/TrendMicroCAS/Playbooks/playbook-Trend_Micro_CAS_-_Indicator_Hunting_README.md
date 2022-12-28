Using the 'trendmicro-cas-email-sweep' command, the playbook enables automated threat hunting and detection of IOCs within email messages in Cloud App Security protected mailboxes.

The playbook displays a list of detected users, internal IP addresses, and external IP addresses corresponding to the specified indicators, along with the results of the 'trendmicro-cas-email-sweep' query.

IOCs included in the playbook are:
IP Addresses ,CIDR ,File Name ,File Type ,SHA1 ,URL ,Domain , and Email Addresses.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Threat Hunting - Set Indicators
* Threat Hunting - Sort Results

### Integrations
* TrendMicro Cloud App Security

### Scripts
* IsIntegrationAvailable
* SetAndHandleEmpty

### Commands
* trendmicro-cas-email-sweep

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileType | A single or multiple IP addresses to search for.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| FileName | Single or multiple file names to search for.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| SHA1 | Single or multiple SHA1 file hashes to search for.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| EmailAddress | A single or multiple email addresses to search for. Used for both recipient and sender email addresses.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| URLDomain | Single or multiple URLs and/or domains to search for<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| IPAddress | A single or multiple IP addresses to search for. Used for both source and destination IP addresses.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| CIDR | A single or multiple IP ranges to search for. Used for both source and destination IP addresses.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| EmailSubject | The subject of email messages for which to search. Use double quotes to search for an exact phrase, for example, "messageA messageB"<br/>otherwise a partial match based on the phrase is performed. For example,<br/>a search is performed on a subject containing messageA, or messageB, or messageA message B.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| start_time | The start time to search for email messages using the date and time format ISO 8601. <br/><br/>For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/><br/>The request searches email messages according to the following settings:<br/>If both start and end are not added, the request searches email messages within seven days \(7 × 24 hours\) before the request was sent.<br/>If both start and end are added, the request searches email messages within this configured duration. Ensure the end time is no earlier than the start time.<br/>If only start is added, the request searches email messages within seven days \(7 × 24 hours\) after the start time.<br/>If only end is added, the request searches email messages within seven days \(7 × 24 hours\) before the end time.<br/><br/>Do not configure lastndays and start/end at the same time |  | Optional |
| end_time | The end time to search for email messages using the date and time format ISO 8601. <br/><br/>For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/><br/>Cloud App Security saves the meta information of email messages for 90 days.<br/>The request searches email messages according to the following settings:<br/>If both start and end are not added, the request searches email messages within seven days \(7 × 24 hours\) before the request was sent.<br/>If both start and end are added, the request searches email messages within this duration. Ensure the end time is no earlier than the start time.<br/>If only start is added, the request searches email messages within seven days \(7 × 24 hours\) after the start time.<br/>If only end is added, the request searches email messages within seven days \(7 × 24 hours\) before the end time.<br/><br/>Do not configure lastndays and start/end at the same time. |  | Optional |
| lastndays | The number of days \(n × 24 hours\) before the request is sent to search.<br/>Do not configure lastndays and start/end at the same time. |  | Optional |
| limit | The maximum number of email messages to display. Maximum is 1,000 email messages. If not specified, default is 20. |  | Optional |
| next_link | The URL for the results page if the total number of email messages in a previous request exceeds the specified limit. When the maximum limit has been exceeded, a URL is specified in the response. To retrieve the remaining email messages, use the URL from the response.	 |  | Optional |
| InternalDomainName | The organizations internal domain name. This is provided for the script IsInternalHostName that checks if the detected host names are internal or external if the hosts contain the internal domains suffix. For example demisto.com. If there is more than one domain, use the \| character to separate values such as \(demisto.com\|test.com\) |  | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HuntingResults.DetectedExternalEmails | External email addresses retrieved from threat hunting queries. | string |
| HuntingResults.DetectedInternalEmails | Internal email addresses retrieved from threat hunting queries. | string |
| HuntingResults.DetectedEmails | A list of all email addresses retrieved from threat hunting queries. Playbook output is generated only when the internal domain name is not specified in the playbook input. | string |
| HuntingResults.DetectedExternalIPs | External IP addresses retrieved from threat hunting queries. | string |
| HuntingResults.DetectedInternalIPs | Internal IP addresses retrieved from threat hunting queries. | string |
| TrendMicroCAS.EmailSweep | API requests details. | unknown |
| TrendMicroCAS.EmailSweep.value.mail_attachments | Trend Micro CAS details retrieved for attachments. | unknown |
| TrendMicroCAS.EmailSweep.value.mail_internet_headers | Trend Micro CAS message header details. | unknown |
| TrendMicroCAS.EmailSweep.value | The details of the detected messages as retrieved from the Trend Micro CAS. | unknown |

## Playbook Image
---
![Trend Micro CAS - Indicator Hunting](../doc_files/Trend_Micro_CAS_-_Indicator_Hunting.png)
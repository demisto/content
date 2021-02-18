This is a multipurpose playbook used for hunting and threat detection. The playbook receives inputs based on hashes, IP addresses, or domain names provided manually or from outputs by other playbooks. 
With the received indicators, the playbook leverages data received by PANW products including, Cortex Data Lake, Autofocus and Pan-OS to search for IP addresses, host names and users related to the provided indicators.
The output provided by the playbook facilitates pivoting searches for possibly affected IP addresses or users.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Convert file hash to corresponding hashes
* PAN-OS Query Logs For Indicators
* Autofocus Query Samples, Sessions and Tags

### Integrations
This playbook does not use any integrations.

### Scripts
* IsInternalHostName
* SetAndHandleEmpty
* IsIPInRanges

### Commands
* cdl-query-threat-logs
* cdl-query-url-logs
* cdl-query-traffic-logs

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SHA256 | SHA256 hash of the indicator to hunt. |  | Optional |
| MD5 | MD5 hash of the indicator to hunt. |  | Optional |
| SHA1 | SHA1 hash of the indicator to hunt. |  | Optional |
| IPAddresses | List of IP addresses. |  | Optional |
| URLDomain | List of domains or urls. |  | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |
| InternalDomainName | The organizations internal domain name. This is provided for the script IsInternalHostName that checks if the detected host names are internal or external if the hosts contain the internal domains suffix. For example demisto.com. If there is more than one domain, use the \| character to separate values such as \(demisto.com\|test.com\) |  | Optional |
| InternalHostRegex | This is provided for the script IsInternalHostName that checks if the detected host names are internal or external. If the hosts match the organization's naming convention. For example the host testpc1 will have the following regex \\w\{6\}\\d\{1\} |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PANWHunting.DetectedUsers | User or array of users that were detected during hunting. | string |
| PANWHunting.DetectedInternalIPs | Internal IP addresses detected based on fields and inputs in your search. | string |
| PANWHunting.DetectedExternalIPs | External IP addresses detected based on fields and inputs in your search. | string |
| PANWHunting.DetectedInternalHosts | Internal host names detected based on fields and inputs in your search. | string |
| PANWHunting.DetectedExternalHosts | External host names detected based on fields and inputs in your search. | string |

## Playbook Image
---
![Palo Alto Networks - Hunting And Threat Detection](https://raw.githubusercontent.com/demisto/content/76c84b8dba7f71dedef605cc1417353222a425b4/Packs/PANWComprehensiveInvestigation/doc_files/Palo_Alto_Networks_-_Hunting_And_Threat_Detection.png)
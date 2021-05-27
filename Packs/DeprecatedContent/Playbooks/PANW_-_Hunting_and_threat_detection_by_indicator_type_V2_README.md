Deprecated. Use the "Palo Alto Networks - Hunting And Threat Detection" playbook instead. Integrations list -  Cortex (Traps, PAN-OS, Analytics)\nThis is a multipurpose playbook used for hunting and threat detection. The playbook receives inputs based on hashes, IP addresses, or domain names provided manually or from outputs by other playbooks. \nWith the received indicators, the playbook leverages Palo Alto Cortex data received by products such as Traps, Analytics and Pan-OS to search for IP addresses and hosts related to that specific hash. \nThe output provided by the playbook facilitates pivoting searches for possibly affected hosts, IP addresses, or users.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Autofocus Query Samples, Sessions and Tags
* PAN-OS Query Logs For Indicators
* Convert file hash to corresponding hashes

### Integrations
* PaloAltoNetworksCortex

### Scripts
* SetAndHandleEmpty
* IsIPInRanges

### Commands
* cortex-query-traffic-logs
* cortex-query-threat-logs
* cortex-query-traps-logs
* cortex-query-analytics-logs

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SHA256 | SHA256 hash for indicator to hunt. |  | Optional |
| MD5 | MD5 hash for indicator to hunt. |  | Optional |
| SHA1 | SHA1 hash for indicator to hunt. |  | Optional |
| IPAddresses | List of IP addresses. |  | Optional |
| URLDomain | List of domains or urls. |  | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PANWHunting.DetectedUsers | User or array of users that were detected during hunting. | string |
| PANWHunting.TrapsId | Id or array of id's for traps hosts detected in the searches. | string |
| PANWHunting.DetectedInternalIPs | Internal IP addresses detected based on fields and inputs in your search. | string |
| PANWHunting.DetectedExternalIPs | External IP addresses detected based on fields and inputs in your search. | string |
| PANWHunting.DetectedInternalHosts | Internal host names detected based on fields and inputs in your search. | string |
| PANWHunting.DetectedExternalHosts | External host names detected based on fields and inputs in your search. | string |

## Playbook Image
---
![PANW_Hunting_and_threat_detection_by_indicator_type_V2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PANW_Hunting_and_threat_detection_by_indicator_type_V2.png)
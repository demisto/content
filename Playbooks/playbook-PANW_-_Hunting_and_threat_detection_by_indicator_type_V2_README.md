Receives inputs based on hashes, IP addresses, or domain names provided manually or from outputs by other playbooks. 
With the received indicators, the playbook leverages Palo Alto Cortex data received by products such as Traps, Analytics and Pan-OS to search for IP addresses and hosts related to that specific hash. 
The output provided by the playbook facilitates pivoting searches for possibly affected hosts, IP addresses, or users.

Integrations list: Cortex (Traps, PAN-OS, Analytics)

This is a multipurpose playbook used for hunting and threat detection. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Query Logs For Indicators
* Autofocus Query Samples, Sessions and Tags
* Convert file hash to corresponding hashes

### Integrations
This playbook does not use any integrations.

### Scripts
* IsIPInRanges
* SetAndHandleEmpty

### Commands
* cortex-query-threat-logs
* cortex-query-traps-logs
* cortex-query-analytics-logs
* cortex-query-traffic-logs

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- | 
| SHA256 | The SHA256 file hash for indicator to hunt. | Optional |
| MD5 | The MD5 file hash for indicator to hunt. | Optional |
| SHA1 | The SHA1 file hash for indicator to hunt. | Optional |
| IPAddresses | The list of IP addresses. | Optional |
| URLDomain | The list of domains or URLs. | Optional |
| InternalRange | The list of internal IP address ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" (without quotation marks). If a list is not provided, the default list provided in the `IsIPInRanges script` (the known IPv4 private address ranges) will be used. | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PANWHunting.DetectedUsers | The user or array of users that were detected during hunting. | string |
| PANWHunting.TrapsId | The ID or array of ID's for traps hosts detected in the searches. | string |
| PANWHunting.DetectedInternalIPs | The internal IP addresses detected based on fields and inputs in your search. | string |
| PANWHunting.DetectedExternalIPs | THe external IP addresses detected based on fields and inputs in your search. | string |
| PANWHunting.DetectedInternalHosts | The internal host names detected based on fields and inputs in your search. | string |
| PANWHunting.DetectedExternalHosts | The external host names detected based on fields and inputs in your search. | string |

## Playbook Image
---
![PANW_Hunting_and_threat_detection_by_indicator_type_V2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PANW_Hunting_and_threat_detection_by_indicator_type_V2.png)

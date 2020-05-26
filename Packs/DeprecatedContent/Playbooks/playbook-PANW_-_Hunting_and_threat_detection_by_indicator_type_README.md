`Deprecated` 

Use the "PANW - Hunting and threat detection by indicator type V2" playbook instead.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Autofocus Query Samples, Sessions and Tags
* PAN-OS Query Logs For Indicators
* Convert file hash to corresponding hashes

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* cortex-query-analytics-logs
* cortex-query-traps-logs
* cortex-query-threat-logs
* cortex-query-traffic-logs

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| SHA256 | The SHA256 hash for indicator to hunt. | SHA256 | File | Optional |
| MD5 | The MD5 hash for indicator to hunt. | MD5 | File | Optional |
| SHA1 | The SHA1 hash for indicator to hunt. | SHA1 | File | Optional |
| IP addresses | The list of IP addresses. | ${IP.Address} | - | Optional |
| Domain | The list of domains or URLs. | ${Domain.Name} | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| detectedips | The IP address or array of IP addresses that were detected during hunting. | string |
| detectedhosts | The Host or array of hosts that were detected during hunting. | string |
| detectedusers | The User or array of users that were detected during hunting. | string |
| trapsid | The ID or array of IDs for traps hosts detected in the searches. | string |

## Playbook Image
---
![PANW_Hunting_and_threat_detection_by_indicator_type](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PANW_Hunting_and_threat_detection_by_indicator_type_V2.png)

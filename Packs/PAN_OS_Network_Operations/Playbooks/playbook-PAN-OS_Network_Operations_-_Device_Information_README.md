Gathers all relevant information for a specific PAN-OS device.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Network Operations - Set Device Domain
* Update Occurred Time

### Integrations
This playbook does not use any integrations.

### Scripts
* DeleteContext

### Commands
* pan-os-platform-get-ha-state
* pan-os-platform-get-system-info
* linkIncidents

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| device | Target | ${incident.panosnetworkoperationstarget} | Optional |
| domain_regex_hostname | If set, will assign this group to the first group retrieved via the regex string. Example; regex of \(\\S\+\)\\-\\S and hostname "nsw-fw01" would set the device domain to "nsw". | (\S+)\- | Optional |
| domain_panorama | If set to "device-group", device will be automatically put in a Domain group based on the device group it's a member of in Panorama. If set to "template-stack", will set the domain to the template-stack this device is a member of. If unset, no grouping is done. | both | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Device Information](../doc_files/PAN-OS_Network_Operations_-_Device_Information.png)
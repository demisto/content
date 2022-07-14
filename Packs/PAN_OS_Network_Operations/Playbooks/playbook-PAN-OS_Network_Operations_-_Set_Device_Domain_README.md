Enables the grouping of devices into administrative domains. Domains may refer to a physical location or logical administrative boundry.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* pan-os-platform-get-template-stacks
* pan-os-platform-get-device-groups
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| domain_regex_hostname | If set, will assign this group to the first group retrieved via the regex string. Example; regex of \(\\S\+\)\\-\\S and hostname "nsw-fw01" would set the device domain to "nsw". | (\S+)\- | Optional |
| domain_panorama | If set to "device-group", device will be automatically put in a Domain group based on the device group it's a member of in Panorama. If set to "template-stack", will set the domain to the template-stack this device is a member of. If unset, no grouping is done. Can also be set to both to add both the template-stack and DG as a domain tag. | both | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Set Device Domain](../doc_files/PAN-OS_Network_Operations_-_Set_Device_Domain.png)
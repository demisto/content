Runs a complete upgrade process for a single device

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Network Operations - Download Software
* GenericPolling
* PAN-OS Network Operations - Install Software

### Integrations
This playbook does not use any integrations.

### Scripts
* Sleep
* Set
* PrintErrorEntry

### Commands
* pan-os-platform-get-available-software
* setIncident
* pan-os-platform-get-system-info
* pan-os-platform-get-device-state
* pan-os-platform-reboot

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| target | Target firewall to upgrade |  | Required |
| target_version | Target version to upgrade to. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Single Device Upgrade](../doc_files/PAN-OS_Network_Operations_-_Single_Device_Upgrade.png)
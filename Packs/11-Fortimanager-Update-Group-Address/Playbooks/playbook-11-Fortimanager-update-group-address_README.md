

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* 11-fortimanager-update-group

### Integrations
* FortiManager

### Scripts
* DeleteContext
* Set

### Commands
* send-mail
* fortimanager-address-group-update
* fortimanager-address-group-list

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| adom |  | fw | Optional |
| ip-object |  | 192.168.7.11 | Optional |
| groupname |  | xsoar | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![11-Fortimanager-update-group-address](Insert the link to your image here)
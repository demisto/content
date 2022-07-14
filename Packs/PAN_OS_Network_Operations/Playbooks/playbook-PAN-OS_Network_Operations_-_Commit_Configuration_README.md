Commits to either a single device, or across all devices in the topology. PAN-OS integration will attempt to only commit to devices that require it, not blanket to all possible devices.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* pan-os-config-get-push-status
* pan-os-config-push-all
* pan-os-platform-get-template-stacks
* pan-os-config-commit
* pan-os-platform-get-device-groups
* pan-os-config-get-commit-status

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| device_filter_string | Commit only on specific devices. Note this does not affect Panorama push operation - to limit the scope of the push, use device_group_filter and template_stack_filter. | ${incident.panosnetworkoperationstarget} | Optional |
| device_group_filter | Panorama Only: If required, a csv list of device-groups to push. If not specified, all device groups will be pushed after a commit. |  | Optional |
| template_stack_filter | Panorama Only: If required, a csv list of template-stacks to push. If not specified, all template stacks will be pushed after a commit. |  | Optional |
| auto_commit | If set to Yes, the configuration will be committed to all firewalls and panorama. If no, a data collection task will prompt for the scope first. | No | Optional |
| auto_push | If set to Yes, the configuration will be automatically pushed to all device groups and template stacks. | No | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Commit Configuration](../doc_files/PAN-OS_Network_Operations_-_Commit_Configuration.png)
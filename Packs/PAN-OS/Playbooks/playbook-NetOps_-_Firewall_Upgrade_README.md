Upgrades the firewall. The superuser is requiered in order to update the PAN-OS version.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Net Simple_Firewall_Upgrade_API_Calls

### Integrations
* Panorama

### Scripts
This playbook does not use any scripts.

### Commands
* pan-os-show-device-version

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| target_version | The target PAN-OS version to upgrade. |Required |
| FirewallInstanceName | The name of the PAN-OS Integration instance for the firewall to upgrade. |Required |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->

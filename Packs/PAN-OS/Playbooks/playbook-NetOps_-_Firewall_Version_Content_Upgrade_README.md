Updates the version and the content of the firewall. The superuser is requiered in order to update the PAN-OS version.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Panorama

### Scripts
This playbook does not use any scripts.

### Commands
* panorama-download-latest-content-update
* panorama-check-latest-panos-software
* panorama-content-update-download-status
* panorama-install-latest-content-update
* panorama-download-panos-version
* panorama-content-update-install-status
* panorama-download-panos-status
* panorama-device-reboot
* panorama-install-panos-version
* panorama-install-panos-status

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| target_version | The target PAN-OS version to upgrade. | targetfirewallversion | incident | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->

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
* pan-os-download-latest-content-update
* pan-os-check-latest-panos-software
* pan-os-content-update-download-status
* pan-os-install-latest-content-update
* pan-os-download-panos-version
* pan-os-content-update-install-status
* pan-os-download-panos-status
* pan-os-device-reboot
* pan-os-install-panos-version
* pan-os-install-panos-status

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| target_version | The target PAN-OS version to upgrade. | targetfirewallversion | incident | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->

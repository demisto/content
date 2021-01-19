This playbook handles a single incident triggered in the PANW IoT (Zingbox) UI by removing a device from quarantine in Cisco ISE.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Cisco ISE
* Palo Alto Networks IoT 3rd Party

### Scripts
* GetCiscoISEActiveInstance
* IsIntegrationAvailable
* isError

### Commands
* panw-iot-3rd-party-report-status-to-panw
* cisco-ise-get-endpoint-id
* cisco-ise-update-custom-attribute 
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident | This playbook is invoked via the incident type "PANW IoT 3rd Party SIEM Integration - Vulnerability". | | yes |

## Playbook Outputs
---
There are no outputs for this playbook.

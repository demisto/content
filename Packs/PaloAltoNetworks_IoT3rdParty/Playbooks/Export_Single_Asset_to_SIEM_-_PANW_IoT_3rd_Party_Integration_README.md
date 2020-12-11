Playbook to handle incident triggered from PANW Iot (Zingbox) UI to send sing Alert or Vulnerability to SIEM.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Syslog Sender
* Palo Alto Networks IoT 3rd Party

### Scripts
* IsIntegrationAvailable
* isError

### Commands
* panw-iot-3rd-party-report-status-to-panw
* panw-iot-3rd-party-convert-assets-to-external-format
* panw-iot-3rd-party-get-single-asset
* send-syslog
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident | This playbook is invoked via the incident type "PANW IoT 3rd Party SIEM Integration - Alert" or PANW IoT 3rd Party SIEM Integration - Vulnerability". | | yes |

## Playbook Outputs
---
There are no outputs for this playbook.

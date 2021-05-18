Gets incremental device, alert, and vulnerability updates from PANW IoT Cloud and sends syslogs to the configured SIEM. This playbook should run every 15 minutes as a scheduled job.

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
* panw-iot-3rd-party-get-asset-list
* send-syslog
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

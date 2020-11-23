Playbook to be run every 15 minutes via a job. Each run will get incremental updates for devices, alerts and vulnerabilities and send syslogs to the configured SIEM server.

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

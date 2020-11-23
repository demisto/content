Playbook to be run every 15 minutes via a job. Each run will get incremental updates for devices from PANW IoT cloud, and will update or create new endpoints in Cisco ISE with PANW IOT discovered attributes (ISE custom attributes)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Cisco ISE
* Palo Alto Networks IoT 3rd Party

### Scripts
* GetCiscoISEActiveInstance
* SendPANWIoTDevicesToCiscoISE
* IsIntegrationAvailable
* isError

### Commands
* panw-iot-3rd-party-report-status-to-panw
* panw-iot-3rd-party-convert-assets-to-external-format
* panw-iot-3rd-party-get-asset-list
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

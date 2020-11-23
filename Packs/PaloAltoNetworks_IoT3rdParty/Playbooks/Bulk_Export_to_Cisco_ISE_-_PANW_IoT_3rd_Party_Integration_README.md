This playbook gets all available device inventory from PANW IoT Cloud and updates/create endpoints with custom attributes on Cisco ISE.
 
## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Cisco ISE
* Palo Alto Networks IoT 3rd Party

### Scripts
* GetCiscoISEActiveInstance
* SendALLPANWIoTDevicesToCiscoISE
* IsIntegrationAvailable
* isError

### Commands
* panw-iot-3rd-party-report-status-to-panw
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

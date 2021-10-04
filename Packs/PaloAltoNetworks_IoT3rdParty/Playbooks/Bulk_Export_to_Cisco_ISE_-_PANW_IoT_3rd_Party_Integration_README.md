Gets the entire available device inventory from PANW IoT Cloud and updates/creates endpoints with custom attributes in Cisco ISE. You should run this playbook as a scheduled job. For example, you might want to schedule the job to run this playbook at the end of each day so that Cisco ISE is updated on a daily basis with the IoT device inventory.
 
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

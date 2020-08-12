This is to run the command 'iot-security-check-servicenow' in the playbook, that's run in a recurring XSOAR job.
The use case is to loop all the opened IoT incidents and query their corresponding ServiceNow ticket status.
If the ticket is closed, the XSOAR incident will be closed.

## Dependencies
This playbook uses the following integration, and script.

## Integrations
* ServiceNow v2

## Scripts
* iot-security-check-servicenow

## Commands
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Palo_Alto_Neworks_IoT_Security_ServiceNow_Check](../../../docs/images/playbooks/Palo_Alto_Neworks_IoT_Security_ServiceNow_Check.png?raw=true)

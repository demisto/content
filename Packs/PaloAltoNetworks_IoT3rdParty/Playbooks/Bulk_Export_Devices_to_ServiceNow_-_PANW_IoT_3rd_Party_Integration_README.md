Gets the entire available device inventory from PANW IoT Cloud and updates/creates endpoints with custom attributes in ServiceNow. You should run this playbook as a scheduled job. For example, you might want to schedule the job to run this playbook at the end of each day so that ServiceNow is updated on a daily basis with the IoT device inventory.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Palo Alto Networks IoT 3rd Party
* ServiceNow v2

### Scripts
* SendAllPANWIoTDevicesToServiceNow

### Commands
* panw-iot-3rd-party-report-status-to-panw

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| status | Sends a status message back to PANW IOT cloud. |  | Required |
| message | Message to be sent to PANW IoT Cloud. |  | Required |
| integrationName | Name of PANW IoT 3rd Party Integration. | servicenow | Required |
| playbookName | Name of the playbook. | Bulk Export Devices to ServiceNow - PANW IoT 3rd Party Integration | Required |
| type | Type of asset associated with the status report. | device | Required |


## Playbook Outputs
---
There are no outputs for this playbook.


Gets updated devices and sends the updates to ServiceNow. You should run this playbook as a scheduled, recurring job.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Palo Alto Networks IoT 3rd Party
* ServiceNow v2

### Scripts
* GeneratePANWIoTDeviceTableQueryForServiceNow

### Commands
* panw-iot-3rd-party-report-status-to-panw
* panw-iot-3rd-party-get-asset-list
* panw-iot-3rd-party-convert-assets-to-external-format
* servicenow-query-table
* servicenow-update-record
* servicenow-create-record


## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| metadata | Example: ServiceNow ID and deviceid mapping |  | Required |
| assetList | List of input assets. |  | Required |
| outputFormat | Desired output format. | ServiceNow | Required |
| assetType | Type of Asset. | Device | Required |
| incrementTime | Increment time in minutes. | 15 | Required |
| devices | Device list. |  | Required |
| status | Sends a status message back to PANW IOT cloud. |  | Required |
| message | Message to be sent to PANW IoT Cloud. |  | Required |
| integrationName | Name of PANW IoT 3rd Party Integration. | servicenow | Required |
| playbookName | Name of the playbook. | Incremental Export Devices to ServiceNow - PANW IoT 3rd Party Integration | Required |
| type | Type of asset associated with the status report. | device | Required |
| table_name | The name of the table in which to create a record. | u_zingbox_discovered_devices | Required |
| fields | Fields and their values to create the record with, in the format: fieldname1=value;fieldname2=value;... |  | Required |
| custom_fields | Custom (user defined) fields in the format: fieldname1=value;fieldname2=value;... |  | Required |
| id | The unique record identifier for the record. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.


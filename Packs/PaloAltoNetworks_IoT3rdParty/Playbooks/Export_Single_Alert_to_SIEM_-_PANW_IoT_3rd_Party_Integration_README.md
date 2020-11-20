This playbook should be used in the Incident Type to let PANW IoT customers to export alerts from PANW IoT (Zingbox) dashboard to ServiceNow.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Palo Alto Networks IoT 3rd Party
* ServiceNow v2

### Scripts
This playbook does not use any scripts.

### Commands
* panw-iot-3rd-party-report-status-to-panw
* panw-iot-3rd-party-get-single-asset
* panw-iot-3rd-party-convert-assets-to-external-format
* servicenow-create-record

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| assetID | Asset ID. zb_ticketid for alert. |  | Required |
| assetType | Type of Asset. | Alert | Required |
| metadata1 | Example: incident triggered by PANW IoT cloud API |  | Required |
| outputFormat | Desired output format. | ServiceNow | Required |
| assetList | List of input assets. |  | Required |
| table_name | The name of the table in which to create a record. | u_zingbox_alerts_vulnerablilty_incident | Required |
| fields | Fields and their values to create the record with, in the format: fieldname1=value;fieldname2=value;... |  | Required |
| status | Each command status |  | Required |
| message | Message send to PANW IoT |  | Required |
| integrationName | Third party integration name | servicenow | Required |
| playbookName | The name of the playbook | Export Single Vulnerability to ServiceNow - PANW IoT 3rd Party Integration | Required |
| type | Name of asset to export to ServiceNow | vulnerability | Required |


## Playbook Outputs
---
There are no outputs for this playbook.


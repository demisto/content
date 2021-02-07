This script takes PANW IoT cloud devices as input and exports them as endpoints with custom attributes in Cisco ISE.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | PANW IoT 3rd Party Integration, Cisco ISE |
| Cortex XSOAR Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Incremental Export to SIEM - PANW IoT 3rd Party Integration

## Dependencies
---
This script uses the following commands and scripts.
* cisco-ise-get-endpoint-id
* cisco-ise-get-endpoint-id-by-name
* cisco-ise-create-endpoint
* cisco-ise-update-endpoint-custom-attribute

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| device_maps | List of device maps from PANW IoT cloud. |
| active_ise_instance | Name of the Active Cisco ISE instance. |
| panw_iot_3rd_party_instance | Name of the configured PANW Iot 3rd Party instance. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoIoTIntegrationBase.Status | Total count of devices updated or created on ISE | unknown |

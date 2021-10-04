Retrieves all devices from PANW IoT Cloud and exports them as endpoints with custom attributes to Cisco ISE.

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
* Bulk Export to Cisco ISE - PANW IoT 3rd Party Integration

## Dependencies
---
This script uses the following commands and scripts.
* panw-iot-3rd-party-get-asset-list
* panw-iot-3rd-party-report-status-to-panw
* cisco-ise-get-endpoint-id
* cisco-ise-get-endpoint-id-by-name
* cisco-ise-create-endpoint
* cisco-ise-update-endpoint-custom-attribute
* GetCiscoISEActiveInstance

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| active_ise_instance | Name of the Active Cisco ISE instance. |
| panw_iot_3rd_party_instance | Name of the configured PANW Iot 3rd Party instance. |

## Outputs
---
There are no outputs for this script.

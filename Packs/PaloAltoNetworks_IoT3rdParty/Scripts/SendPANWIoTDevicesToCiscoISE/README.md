This script takes in PANW IoT cloud devices as input and exports them as Endpoints with custom attributes in Cisco ISE
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | PANW IoT 3rd Party Integration, Cisco ISE |
| Demisto Version | 6.0.0 |

This Scripts uses the following commands:
'cisco-ise-get-endpoint-id' or 'cisco-ise-get-endpoint-id-by-name' - Gets an ID for an endpoint
'cisco-ise-update-endpoint-custom-attribute' - For updating an endpoints custom attributes

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| device_maps | List of device maps from PANW IoT cloud. |
| active_ise_instance | Name of the Active Cisco ISE instance. |

## Outputs
---
There are no outputs for this script.

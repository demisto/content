Determines which configured Cisco ISE instance is in active/primary state and returns the name of the instance.

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
* Un-quarantine Device in Cisco ISE - PANW IoT 3rd Party Integration
* Quarantine Device in Cisco ISE - PANW IoT 3rd Party Integration
* Incremental Export to Cisco ISE - PANW IoT 3rd Party Integration

## Dependencies
---
This script uses the following commands and scripts.
* cisco-ise-get-nodes

This Scripts uses the following commands:
'cisco-ise-get-nodes' - Gets data for all Cisco ISE nodes in the current deployment

## Inputs
---

There are no inputs for this script.

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoIoTIntegrationBase.ActiveNodeInstance | Returns instance name of the active Cisco ISE node. | unknown |
| PaloAltoIoTIntegrationBase.NodeErrorStatus | Returns the nodes error status if no active Cisco ISE nodes are found. | unknown |

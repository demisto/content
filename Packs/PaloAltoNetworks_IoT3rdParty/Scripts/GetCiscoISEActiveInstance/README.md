This scripts determines which configured Cisco ISE instance is in active/primary state and returns the name of this instance.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | PANW IoT 3rd Party Integration, Cisco ISE |
| Demisto Version | 6.0.0 |

This Scripts uses the following commands:
'cisco-ise-get-nodes' - Gets data for all Cisco ISE nodes in the current deployment

## Inputs
---

There are no inputs for this script.

## Outputs
---

| **Pathe** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoIoTIntegrationBase.ActiveNodeInstance | Returns instance name of the active Cisco ISE node. | unknown |
| PaloAltoIoTIntegrationBase.NodeErrorStatus | Returns the nodes error status if no active Cisco ISE nodes are found. | unknown |

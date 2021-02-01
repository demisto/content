Assigns analysts who are not out of the office to the shift handover incident. Use the ManageOOOusers automation to add or remove analysts from the out-of-office list.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Shift Management, ooo |
| Demisto Version | 5.5.0 |

## Used In
---
This script is used in the following playbooks and scripts.
Shift handover

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| roles | The list of roles from which to assign analysts to the shift handover incident. Can be an array or a comma-separated list. Leave empty to assign all analysts. |
| oncall | Whether to randomly assign analysts who are on call for the shift handover.  Possible values: "true" and "false". Requires Cortex XSOAR v5.5 or later. |
| listname | The name of the out-of-office list. Default is "OOO List". |
| assignAll | Whether to assign all on-call analysts to the shift handover incident. Set to "true" to assign all on-call analysts. |

## Outputs
---
There are no outputs for this script.

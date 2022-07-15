Adds or removes an analyst from the out-of-office list in XSOAR. When used with the AssignAnalystToIncidentOOO automation, prevents incidents from being assigned to an analyst who is out of office.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ooo, Shift Management |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| option | Add or remove an analyst from the out-of-office list. Possible values are "Add" and "Remove". |
| daysoff | Number of days the analyst will be off. Default is 7. |
| listname | A list to use in place of the out-of-office list. If the name of the list that you pass does not begin with OOO, the script automatically prefixes OOO to the script name. For example, if you pass a list called newList, the script will automatically change the name to OOO newList. Default is "OOO List". |
| username | The name of the analyst to add to the list. The default is the current analyst. Must be provided when running as part of a playbook. |

## Outputs
---
There are no outputs for this script.

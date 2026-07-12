Syncs the DSPM violation status from XSOAR to RSC.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | field-change-triggered |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| violation_id | The ID of the DSPM Violation.<br/><br/>Note: If not provided, the script will try to retrieve it from the incident context. |
| violation_status | The status to update for violation.<br/><br/>Note: If not provided, the script will try to retrieve it from the incident context. |

## Outputs

---
There are no outputs for this script.

Syncs the DSPM violation information from RSC to XSOAR.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| violation_id | The ID of the DSPM Violation.<br/><br/>Note: If not provided, the script will try to retrieve it from the incident context. |
| object_id | The Object ID.<br/><br/>Note: If not provided, the script will try to retrieve it from the incident context. |
| snapshot_id | The Snapshot ID.<br/><br/>Note: If not provided, the script will try to retrieve it from the incident context. |
| limit | Number of results to retrieve in the response. The maximum allowed size is 1000. |

## Outputs

---
There are no outputs for this script.

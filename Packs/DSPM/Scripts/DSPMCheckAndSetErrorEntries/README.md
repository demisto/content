This script checks for error entries based on provided entry IDs and returns "yes" if any errors are found or "no" if no errors are present. If errors are detected, it sets the error messages in the XSOAR context.

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
| entry_id | Entry to check. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| yes | If one or more entries is an error. | Unknown |
| no | If none of the entries is not an error. | Unknown |

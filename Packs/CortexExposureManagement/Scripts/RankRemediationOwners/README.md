Recommend most likely remediation owners from those surfaced by other enrichments.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* setIssue

## Used In

---
This script is used in the following playbooks and scripts.

* Cortex EM - Exposure Issue

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| owners | List of potential remediation owners. |
| system_ids | System IDs or names associated with the compute instance. |
| ownerrelatedfield | The field of the alert or issue in which the owners should be stored. |
| tenantcommand | False will use \!setAlert, True will use \!setIssue. |

## Outputs

---
There are no outputs for this script.

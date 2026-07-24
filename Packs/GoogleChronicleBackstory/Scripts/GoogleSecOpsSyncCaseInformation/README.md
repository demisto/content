Syncs the latest case information, related alerts and alert entities from Google SecOps and updates the XSOAR incident data.

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
| case_id | Specify the ID of the Google SecOps Case to sync.<br/><br/>Note: If not provided, the script will try to retrieve it from the incident context. |
| alert_page_size | Specify the maximum number of alerts to retrieve.<br/><br/>Note: Maximum value is 1000. |
| entity_page_size | Specify the maximum number of entities to retrieve per alert.<br/><br/>Note: Maximum value is 1000. |

## Outputs

---
There are no outputs for this script.

This script is an example script of how to retrieve an incident from Cherwell. The script wraps the cherwell-get-business-object command of the cherwell integration. When writing your own script to get a business object, follow the instructions found in the configuration section of the script, but do not change the execution section.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Cherwell |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* cherwell-get-business-object

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| id_type | Type of ID. |
| id_value | Public ID or record ID. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Cherwell.BusinessObjects.RecordId | Recoed ID | String |
| Cherwell.BusinessObjects.PublicId | Public ID | String |
| Cherwell.BusinessObjects.Description | Incident description | String |
| Cherwell.BusinessObjects.Priority | Incident ptiority | Number |
| Cherwell.BusinessObjects.OwnedBy | Incident owned by field | String |
| Cherwell.BusinessObjects.Service | Service needed for the incident | String |
| Cherwell.BusinessObjects.CustomerDisplayName | Incident reporting customer  | String |
| Cherwell.BusinessObjects.CreatedDateTime | Created date time | Date |
| Cherwell.BusinessObjects.TotalTasks | Total tasks for this incident | Number |

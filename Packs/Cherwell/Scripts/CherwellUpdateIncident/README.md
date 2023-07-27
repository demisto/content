This script is an example script of how to update an incident in Cherwell. The script wraps the update-business-object command of the cherwell integration. When writing your own script to update a business object, follow the instructions found in the configuration section of the script, but do not change the execution section.

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

* cherwell-update-business-object

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| description | Incident description. |
| priority | Incident priority. |
| owned_by | Incident owner. |
| service | Service needed. |
| id_value | Public ID or record ID. |
| id_type | Type of ID. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Cherwell.BusinessObjects.PublicId | Incident public ID | String |
| Cherwell.BusinessObjects.RecordId | Incident record ID | String |

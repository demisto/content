This script is an example script of how to create an incident in Cherwell. The script wraps the create business object command in the cherwell integration. When writing your own script to create a business object, follow the instructions in the configuration part, but do not change the execution section.

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

* cherwell-create-business-object

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| description | Incident description. |
| priority | Incident priority. |
| owned_by | Incident owner. |
| service | Service needed. |
| customer_display_name | Requesting customer name. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Cherwell.BusinessObjects.PublicId | Incident public ID | String |
| Cherwell.BusinessObjects.RecordId | Incident record ID | String |

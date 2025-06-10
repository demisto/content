Find custom scripts and integration dependencies used inside of playbooks.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |


## Dependencies
---
This script uses the following commands and scripts.

* core-api-post
* Core REST API
  

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| mode | Finds all the playbooks used by custom scripts and enabled integrations. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FindPlaybookCustomDependencies.CustomDependencies.CustomScripts | Context Path for the outputs of the playbooks using a custom script | Unknown |
| FindPlaybookCustomDependencies.CustomDependencies.CustomIntegrations | Context Path for the outputs of the playbooks using a custom integrations | Unknown |

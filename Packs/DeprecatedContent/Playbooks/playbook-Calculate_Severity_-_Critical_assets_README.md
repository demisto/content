DEPRECATED. Use "Calculate Severity - Critical Assets v2" playbook instead. Determines if a critical assest is associated with the invesigation. The playbook returns a severity level of "Critical" if a critical asset is associated with the investigation.

This playbook verifies if a user account or an endpoint is part of a critical list or a critical AD group. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| CriticalUsers | The array of usernames of critical users (comma-separated). | - | - | Optional |
| CriticalEndpoints | The array of hostnames of critical endpoints (comma-separated). | - | - | Optional |
| CriticalGroups | The array of DN names of critical AD groups (comma-separated). | - | - | Optional |
| Account | The user account to check against the critical lists. | None | Account | Optional |
| Endpoint | The endpoint to check against the critical lists. | None | Endpoint | Optional |


## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Severity | The output severity | string |

## Playbook Image
---
![Calculate_Severity_Critical_assets](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Calculate_Severity_Critical_assets.png)

Deprecated. Use Calculate Severity - Critical Assets v2 playbook instead. Determines if a critical assest is associated with the invesigation. The playbook returns a severity level of \"Critical\" if a critical asset is associated with the investigation.\n\nThis playbook verifies if a user account or an endpoint is part of a critical list or a critical AD group.

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

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| CriticalUsers | Array of usernames of critical users \(comma separated\). |  | Optional |
| CriticalEndpoints | Array of hostnames of critical endpoints \(comma separated\). |  | Optional |
| CriticalGroups | Array of DN names of critical AD groups \(comma separated\). |  | Optional |
| Account | A user account to check against the critical lists. | Account.None | Optional |
| Endpoint | An endpoint to check against the critical lists. | Endpoint.None | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Severity | The output severity | string |

## Playbook Image
---
![Calculate Severity - Critical assets](Insert the link to your image here)
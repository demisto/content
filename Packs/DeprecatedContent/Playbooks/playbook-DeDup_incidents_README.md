Deprecated. Check for duplicate incidents for the current incident, and close it if any duplicate has found.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* CloseInvestigationAsDuplicate
* FindSimilarIncidents

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| similarIncidentKeys | Identical incident keys |  | Optional |
| similarLabels | Identical\\Similar labels keys.<br/>You allow difference in X words between labels. For example, the input:<br/>Email\\subject:2,Email\\from<br/>Will demand:<br/>1. Email\\from to be identical <br/>2. Email\\subject to be similar with 2 max words difference<br/> |  | Optional |
| similarContextKeys | Identical\\Similar context keys.<br/>You allow difference in X words between values.  |  | Optional |
| similarCustomFields | Identical\\Similar custom fields.<br/>You allow difference in X words between values. |  | Optional |
| hoursBack | Check incidents within X hours back. | 24 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| isSimilarIncidentFound | Is similar incident found? \(true\\false\) | unknown |

## Playbook Image
---
![DeDup incidents](Insert the link to your image here)
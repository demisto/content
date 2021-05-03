Deprecated. Check for duplicate incidents for the current incident, and close it if any duplicate has been found by machine-learning  find duplicates automation.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Print
* CloseInvestigationAsDuplicate
* GetDuplicatesMlv2

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| closeThreshold | Candidate with score above this threshold will close the investigation automatically, and mark as duplicate to the current incident. | 0.75 | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| foundDuplicates | found any duplicate incident? | boolean |
| duplicateCandidate | the duplicate top candidate | unknown |

## Playbook Image
---
![DeDup incidents - ML](Insert the link to your image here)
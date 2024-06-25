DEPRECATED. Use "Dedup - Generic v2" playbook instead. Identifies duplicate incidents using one of the supported methods.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
This playbook does not use any integrations.

## Scripts
* FindSimilarIncidentsByText
* FindSimilarIncidents
* CloseInvestigationAsDuplicate
* GetDuplicatesMlv2

## Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| DuplicateMethod | Select a method for identifying duplicate incidents. Can be, "ml", "rules", or "text". | ml | Required |
| DuplicateThreshold | The similarity threshold to consider an incident as a duplicate. Can be, "0" or "1". Chose "1" when it is a duplicate and "0" when it is not a duplicate. Use this argument in the ML or text methods. | 0.75 | Required |
| TimeFrameHours | The time frame (in hours) in which to check for duplicate incident candidates. | 72 | Required |
| IgnoreCloseIncidents | Whether to ignore closed incidents. Can be, "yes" or "no". | yes | Required |
| MaxNumberOfCandidates | The maximum number of candidates to check for duplication. | 1000 | Optional |
| CloseAsDuplicate | Whether to close incidents identified as duplicates. Can be, "true" or "false". | true | Optional |
| TimeField | The time field by which to query past incidents to check for duplicate incident candidates. The values can be, "created", "occurred", or "modified". | created | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| isSimilarIncidentFound | Whether a similar incident was found. Can be, "true" or "false". | boolean |
| similarIncident | The similar incident. | unknown |

## Playbook Image
---
![Dedup_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Dedup_Generic.png)

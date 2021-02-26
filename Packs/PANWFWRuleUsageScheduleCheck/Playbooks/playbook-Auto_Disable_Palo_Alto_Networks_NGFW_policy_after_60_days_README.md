

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Palo Alto Sam Version

### Scripts
This playbook does not use any scripts.

### Commands
* panorama-show-rule-hit-count
* closeInvestigation
* panorama-commit
* panorama-disable-rule
* panorama-commit-status

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TimeStampCompare.Result | Whether the tested time was before, after, or equal to the comapred time. | String |

## Playbook Image
---
![Auto Disable Palo Alto Networks NGFW policy after 60 days](Insert the link to your image here)
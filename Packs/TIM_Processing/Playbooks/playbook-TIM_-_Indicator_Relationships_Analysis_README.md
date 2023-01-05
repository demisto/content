This playbooks allows you to analyze indicator relationships for investigation purposes. the playbook will provide the following relationships:
- Related IOCs
- Related Attack Patterns
- Related Campaign
- IOC's related to the campaign
- Report that contains the campaign



## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* SearchIndicatorRelationships
* Set

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator | Input indicator to analyze his relationships |  | Optional |
| LimitResults | The number of results to return. if the input is empty than the limit will be 20 | 200 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RelatedAttackPatterns | Attack patterns related to the indicator | unknown |
| RelatedCampaign | Campaign related to the indicator | unknown |
| RelatedReport | Report related to the campaign | unknown |
| RelatedFiles | Files related to the indicator and campaign | unknown |
| RelatedDomains | Domains related to the indicator and campaign | unknown |
| RelatedIPs | IPs related to the indicator and campaign | unknown |
| RelatedURLs | URLs related to the indicator and campaign | unknown |

## Playbook Image
---
![TIM - Indicator Relationships Analysis](../doc_files/TIM_-_Indicator_Relationships_Analysis.png)
Populates indicators from PhishLabs, according to a defined period of time.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
* PhishLabsPopulateIndicators

### Commands
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| Since | Get indicators within this duration (from now). | 1h | Optional |
| Limit | The maximum number of indicators. | - | Optional |
| Remove protocol | Removes the protocol part from indicators, when the rule can be applied. | false | Optional |
| Remove query | Removes the query string part from indicators, when the rules can be applied. | false | Optional |
| Indicator type | The filter of the indicators by indicator type. | - | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PhishLabsPopulateIndicators](../doc_files/PhishLabsPopulateIndicators.png)

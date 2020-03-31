Whitelists indicators from PhishLabs that were classified as false positives, according to a defined period of time.

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
| Since | The whitelist indicators within this duration (from now). | 1h | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

![PhishLabsWhitelistIndicators](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/PhishLabsWhitelistIndicators.png)

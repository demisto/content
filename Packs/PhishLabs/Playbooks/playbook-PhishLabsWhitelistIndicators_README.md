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

## Playbook Image
---
![PhishLabsWhitelistIndicators](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PhishLabsWhitelistIndicators.png)

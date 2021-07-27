This playbook blocks malicious Domains using all integrations that are enabled.

Supported integrations for this playbook:
* Zscaler
* Symantec Messaging Gateway
* FireEye EX
* Trend Micro Apex One
* Proofpoint Threat Response

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block Domain - FireEye Email Security
* Block Domain - Proofpoint Threat Response
* Block Domain - Zscaler
* Block Domain - Symantec Messaging Gateway 
* Block Domain - Trend Micro Apex One

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The Domain to block. |  | Optional |
| DomainBlackListID | The Domain List ID to add the Domain to.<br/>product: Proofpoint Threat Response |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Block Domain - Generic](https://raw.githubusercontent.com/demisto/content/7d20d193ddfe06ad3ead0effb87db3e71fe675a8/Packs/CommonPlaybooks/doc_files/Block_Domain_-_Generic.png)
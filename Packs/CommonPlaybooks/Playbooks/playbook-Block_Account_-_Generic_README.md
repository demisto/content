Blocks malicious usernames using all integrations that you have enabled.

Supported integrations for this playbook:
* Active Directory

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
* activedir

## Scripts
This playbook does not use any scripts.

## Commands
* ad-disable-account

## Playbook Inputs
---

| **Name** | **Description** |  **Required** |
| --- | --- | --- | 
| Username | The array of malicious usernames to block. |  Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Block_Account_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_Account_Generic.png)

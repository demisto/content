This playbook will block email address at your email gateway.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
integration-Symantec_Messaging_Gateway

### Scripts
IsIntegrationAvailable

### Commands
smg-block-email

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| EmailToBlock | The email address that will be blocked. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Symantec block Email](https://raw.githubusercontent.com/demisto/content/cfbc35e7b18342a51fffb90c9c78f0020855a206/Packs/Symantec_Messaging_Gateway/doc_files/Symantec_block_Email.png)

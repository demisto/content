This playbook will block emails at your mail relay integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Symantec block Email
Mimecast - Block Sender Email

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
| EmailToBlock | The email address that will be blocked. |  | Optional |
| MimecastBlockGroup | The name of the Mimecast block group to add emails to. |  | Optional |
| MimecastQuerySource | The query source of Mimecast, please input "cloud" or "ldap". |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Block Email - Generic](https://raw.githubusercontent.com/demisto/content/605f19009e479d6665e545748a777e23b9ec5365/Packs/CommonPlaybooks/doc_files/Block_Email_-_Generic.png)

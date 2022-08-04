This playbook will block emails at your mail relay integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Symantec block Email

### Integrations
This playbook does not use any integrations.

### Scripts
* IsIntegrationAvailable

### Commands
* mimecast-create-policy
* fireeye-ex-update-blockedlist
* cisco-email-security-list-entry-add

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| EmailToBlock | The email address that will be blocked. | test3@test.com | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Block Email - Generic v2](../doc_files/Block_Email_-_Generic_v2.png)
A playbook to block sender email address using Mimecast integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MimecastV2

### Scripts
* IsIntegrationAvailable

### Commands
* mimecast-find-groups
* mimecast-add-group-member

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| BlockGroup | The sender email block group. |  | Required |
| SenderEmail | The sender email to block. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Mimecast - Block Sender Email](../doc_files/Mimecast_-_Block_Sender_Email.png)
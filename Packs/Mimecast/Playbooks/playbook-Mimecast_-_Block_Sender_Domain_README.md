A playbook to block sender domain name using Mimecast integration.

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
| SenderDomain | The sender domain to block. |  | Required |
| QuerySource | The query source, please input cloud or ldap in the value input. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

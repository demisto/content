Blocks a domain by adding it to an existing Netskope URL List.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Netskope - Direct to Zero Trust

### Scripts

This playbook does not use any scripts.

### Commands

* netskopev2-add-url

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The domain to block. |  | Required |
| ListName | Name of an existing Netskope URL List to add the domain to. Must already exist - this pack has no create-list command. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

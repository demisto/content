This playbook blocks domains using Cisco Stealthwatch.
The playbook checks whether the Cisco Stealthwatch integration is enabled, whether the Domain input has been provided and if so, blocks the domain.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

- Stealthwatch Cloud

### Scripts

This playbook does not use any scripts.

### Commands

- sw-block-domain-or-ip

## Playbook Inputs

---

| **Name** | **Description**      | **Default Value** | **Required** |
| -------- | -------------------- | ----------------- | ------------ |
| Domain   | The Domain to block. |                   | Optional     |

## Playbook Outputs

---

There are no outputs for this playbook.

## Playbook Image

---

![Block Domain - Cisco Stealthwatch](../doc_files/CiscoStealthwatch-Block-Domain-Playbook.png)

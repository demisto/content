This playbook remediates the following Prisma Cloud AWS IAM User alerts.

Prisma Cloud policies remediated:

 - AWS IAM user has two active Access Keys

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* Print

### Commands

* aws-iam-list-access-keys-for-user
* aws-iam-update-access-key

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| policyId | Prisma Cloud policy Id. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

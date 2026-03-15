This playbook remediates the following Prisma Cloud GCP Compute Engine VM Instance alerts.

Prisma Cloud policies remediated:

 - GCP VM instances have serial port access enabled
 - GCP VM instances have block project-wide SSH keys feature disabled
 - GCP VM instances without any custom metadata information

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Google Cloud Compute

### Scripts

This playbook does not use any scripts.

### Commands

* gcp-compute-get-instance
* gcp-compute-set-instance-metadata

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| policyId | Prisma Cloud policy Id. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.
This playbook contains all the cloud provider sub playbooks for remediation

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Azure - Network Security Group Remediation
* AWS - Security Group Remediation
* AWS - Unclaimed S3 Bucket Remediation
* GCP - Firewall Remediation

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
| RemediationRule | The security group that will be used for remediating internet exposures.  | Remediation-Security-Group | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Remediation](../doc_files/Cortex_ASM_-_Remediation.png)

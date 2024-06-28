This playbook contains all the cloud provider sub playbooks for remediation.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex ASM - On Prem Remediation
* AWS - Unclaimed S3 Bucket Remediation
* GCP - Firewall Remediation
* Azure - Network Security Group Remediation
* Cortex ASM - Cortex Endpoint Remediation
* AWS - EC2 Package Upgrade
* AWS - Security Group Remediation v2

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
| AWSAssumeRoleName | If assuming roles for AWS, this is the name of the role to assume \(should be the same for all organizations\) |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Remediation](../doc_files/Cortex_ASM_-_Remediation.png)

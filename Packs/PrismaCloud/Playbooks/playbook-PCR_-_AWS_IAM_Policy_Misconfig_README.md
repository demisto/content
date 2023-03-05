Remediates Prisma Cloud AWS IAM policy alerts.  It uses sub-playbooks that perform the remediation steps.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Prisma Cloud Remediation - AWS IAM Password Policy Misconfiguration

### Integrations
* PrismaCloud v2
* Builtin

### Scripts
This playbook does not use any scripts.

### Commands
* closeInvestigation
* aws-iam-get-account-password-policy
* redlock-dismiss-alerts

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| AutoUpdatePasswordPolicy | Whether to update AWS IAM password policy automatically. | no | - | Optional |
| policyId | Returns the Prisma Cloud policy ID. | labels.policy | incident | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PCR_AWS_IAM_Policy_Misconfig](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PCR_AWS_IAM_Policy_Misconfig.png)

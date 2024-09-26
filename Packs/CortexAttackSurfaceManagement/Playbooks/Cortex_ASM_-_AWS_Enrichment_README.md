Given the IP address this playbook enriches AWS information relevant to ASM alerts.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* AWS - Enrichment
* AWS - Unclaimed S3 Bucket Validation

### Integrations

This playbook does not use any integrations.

### Scripts

* GridFieldSetup
* Set

### Commands

* setAlert

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | IP address of service | alert.remoteip | Optional |
| ASMRuleID | Attack Surface Management Rule ID. | alert.asmattacksurfaceruleid | Required |
| AWSAssumeRoleName | If assuming roles for AWS, this is the name of the role to assume \(should be the same for all organizations\). |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - AWS Enrichment](../doc_files/Cortex_ASM_-_AWS_Enrichment.png)

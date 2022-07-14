Remediates issues with security profiles.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* panorama-create-anti-spyware-best-practice-profile
* panorama-create-vulnerability-best-practice-profile
* panorama-create-url-filtering-best-practice-profile

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| auto_remediate | True if the profile issues should be automatically fixed. | false | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Visibility Hygiene - Profile Issue Remediation](../doc_files/PAN-OS_Network_Operations_-_Visibility_Hygiene_-_Profile_Issue_Remediation.png)
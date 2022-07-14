Remediates Visibility Hygiene issues.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Network Operations - Visibility Hygiene - Profile Issue Remediation
* PAN-OS Network Operations - Visibility Hygiene - Security Rule Visibility
* PAN-OS Network Operations - Commit Configuration
* PAN-OS Network Operations - BPA Wrapper

### Integrations
This playbook does not use any integrations.

### Scripts
* DeleteContext
* Set

### Commands
* linkIncidents
* pan-os-hygiene-fix-log-forwarding
* setIncident
* pan-os-hygiene-fix-security-zone-log-settings
* setPlaybook

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| supported_codes | The list of supported codes for automatic remediation. | BP-V-3 BP-V-4 BP-V-5 BP-V-6 BP-V-7 BP-V-8 BP-V-9 BP-V-10 | Optional |
| auto_remediate | If set, any issues that this playbook can automatically remediate without threat of traffic interruption will be done. | false | Optional |
| auto_commit | If set to Yes, the remediated configuration will be automatically committed to the firewalls and Panorama. | false | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Visibility Hygiene Remediation](../doc_files/PAN-OS_Network_Operations_-_Visibility_Hygiene_Remediation.png)
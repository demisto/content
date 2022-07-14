Checks a specific version of software for any open CVEs, and if they exist, starts a domain upgrade for that system to a fixed version.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* CheckPanosVersionAffected

### Commands
* createNewIncident
* pan-advisories-get-advisories

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| panos_version | Software version to check. |  | Required |
| minimum_cvss_score | Minimum CVSS score to initiate the upgrade process. | 7.0 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Check Version for CVEs](../doc_files/PAN-OS_Network_Operations_-_Check_Version_for_CVEs.png)
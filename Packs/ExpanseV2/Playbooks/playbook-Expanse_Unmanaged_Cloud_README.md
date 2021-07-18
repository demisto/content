Subplaybook for bringing rogue cloud accounts under management.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* This does not use any sub-playbooks

### Integrations
* ExpanseV2

### Scripts
* This playbook does not use any scripts.

### Commands
* domain
* certificate
* expanse-get-issue
* expanse-get-services

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ExpanseCloudManagedIssueId | ID of Expanse Issue | incident.expanseissueid | Optional |
| ExpanseCloudManagedIPv4 | IPv4 of Cloud asset | incident.labels.ip | Optional |
| ExpanseCloudManagedEmailBody | Email body to send to potential owner | Infosec has identified a security issue on a cloud service we believe may belong to you or your team. This asset or service does not appear to be behind proper compliance controls. \n\nPlease get in touch with your Infosec team to define proper remediation access. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Expanse Check ServiceNow CMDB](https://raw.githubusercontent.com/demisto/content/master/Packs/ExpanseV2/doc_files/Expanse_Unmanaged_Cloud.png)

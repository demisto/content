Cluster Report Categorization playbook is used to retrieve the reports of specific clusters and perform the categorization of reports.

Users are only able to run the playbook in v6.0.0 or higher as it requires commands to execute the task.
## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Report Categorization - Cofense Triage v3

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* cofense-report-list
* cofense-cluster-list

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Tags | Specify the tags to retrieve the cluster. |  | Required |
| MatchPriority | Specify the priority to retrieve the cluster based on the priority of the rules that match the reports in the cluster. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cluster Report Categorization - Cofense Triage v3](./../doc_files/Cluster_Report_Categorization_-_Cofense_Triage_v3.png)
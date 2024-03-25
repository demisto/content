This playbook is a sub playbook of the "Prisma Cloud Compute - Jira Compliance Issue" playbook.
It creates a new Jira issue or updates an existing Jira issue with a markdown table for the given compliance ID retrieved from the parent playbook, with enriched data for each resource (host, image or container).

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* SetAndHandleEmpty
* DeleteContext

### Commands

* jira-create-issue
* jira-issue-query
* jira-edit-issue
* jira-issue-delete-file

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Filter | A filter to use for filtering relevant compliance issues. |  | Optional |
| ComplianceIssueID | The compliance issue id to open a ServiceNow ticket for. |  | Optional |
| ComplianceIssueDescription | The compliance issue description. |  | Optional |
| ComplianceIssueSeverity | The compliance issue severity. |  | Optional |
| JiraIssueTypeName |  |  | Optional |
| JiraProjectName |  |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TicketAction | What was the ticket action - create or update. | string |
| Ticket | The ticket object which was created or updated. | string |

## Playbook Image

---

![Prisma Cloud Compute - Jira Ticket (Markdown Table)](../doc_files/Prisma_Cloud_Compute_-_Jira_Ticket_(Markdown_Table).png)

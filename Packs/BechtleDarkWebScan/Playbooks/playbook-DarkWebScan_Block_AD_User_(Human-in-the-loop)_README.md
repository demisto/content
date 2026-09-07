Gets the affected username of a Bechtle Dark Web Scan issue, then sends an email for human confirmation if the affected user should be blocked.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Active Directory Query v2

### Scripts

* IsIntegrationAvailable
* SearchIncidentsV2

### Commands

* ad-disable-account
* ad-get-user
* closeInvestigation
* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IssueID | Issue ID | ${issue.id} | Optional |
| Severity | Issue Severity | ${issue.severity} | Optional |
| Details | Issue Details | ${issue.details} | Optional |
| IssueUsername | Username as reported from the Dark Web Scan Integration Evidence | ${issue.labels.username} | Optional |
| UsernameWithoutDomain | The username but with the mail domain removed \(e.g. @example.org\) | issue.labels.username | Optional |
| SendMailsTo | Send all email notifications from this playbook to this email address | -bogus@example.org | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![DarkWebScan Block AD User (Human-in-the-loop)](../doc_files/DarkWebScan_Block_AD_User_(Human-in-the-loop).png)

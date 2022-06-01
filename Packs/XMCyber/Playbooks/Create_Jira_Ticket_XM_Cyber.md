This playbook goal is to create a new task in Jira, based on XM's risk score data.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts:
* XM Cyber integration

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* XMCyber

### Scripts


### Commands
* jira-create-issue

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Project Name | Name of the project in Jira to add tasks from XM Cyber | '' | Mandatory |
| Project Key | The key with which to associate this issue | XM Security Score Trend | Optional |

## Playbook Outputs
---

## Playbook Image
---
![Create Jira Ticket - XM Cyber](https://github.com/matan-xmcyber/content/blob/master/docs/images/playbooks/Create_Jira_Ticket_XM_Cyber.png)
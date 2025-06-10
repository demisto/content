This playbook automates the dispatching of issues through ServiceNow v2 or Jira v3 and notifies stakeholders via Slack v3, Microsoft Teams, and/or email. With this playbook you can choose to create or update a ticket using Jira or ServiceNow, notify other teams using Slack or Microsoft Teams, and/or by sending an Email. It gives you the flexibility to create a ticket only and skip the notification step, skip the creation of a ticket and notify only, or choose to create a ticket and notify stakeholders. The playbook checks for and requires existing Jira, ServiceNow, Slack, or Microsoft Teams integrations to perform the ticketing and notification actions. If none of these integrations are found in your account, then the playbook sends an email with the issue details to the selected issue owner. 

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Jira V3
* Microsoft Teams
* ServiceNow v2
* SlackV3
* mail-sender

### Scripts

This playbook does not use any scripts.

### Commands

* jira-create-issue-quick-action
* jira-issue-add-comment
* send-mail
* servicenow-create-ticket-quick-action
* servicenow-update-ticket
* slack-send-notification-quick-action
* teams-send-notification-quick-action

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Preferred ticketing platform | Accepted values <br/>- Jira<br/>- ServiceNow<br/>- Both<br/><br/>Note: Leaving this blank will prevent issue ticket from being generated and the playbook will skip this step. |  | Optional |
| Preferred notification platform | Accepted values <br/>- Microsoft Teams<br/>- Slack<br/><br/>Note: Leaving this blank will prevent sending notification message and the playbook will skip this step. |  | Optional |
| Notification email recipients | Provide the email address to send email notification.<br/><br/>Note: Leaving this blank will prevent sending email notification and the playbook will skip this step. |  | Optional |
| System Input - Asset details | Note: No input is required here; issue asset details will be automatically pulled from the remediation playbook. |  | Optional |
| System Input - Issue State | Note: No input is required here; issue state value will be automatically entered from the remediation playbook. |  | Optional |
| System Input -ServiceNow Ticket ID | Note: No input is required here; ServiceNow ticket ID will be automatically pulled from the remediation playbook. |  | Optional |
| System Input -Jira Ticket ID | Note: No input is required here; Jira ticket ID will be automatically pulled from the remediation playbook. |  | Optional |
| Jira Project Key | Provide Jira project key where the issue will be created. |  | Optional |
| Teams Channel Name | Provide Microsoft Teams channel name to which to send messages. |  | Optional |
| Slack Channel Name | Provide Slack channel name to which to send messages. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Ticket.Id | Jira Ticket ID | string |
| ServiceNow.Ticket.ID | Service Now Ticket ID | string |

## Playbook Image

---

![Create Ticket and Notify](../doc_files/Create_Ticket_and_Notify.png)

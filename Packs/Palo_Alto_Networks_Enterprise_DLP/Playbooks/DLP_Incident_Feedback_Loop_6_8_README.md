Collects feedback from user  about blocked files.

## Dependencies

This playbook handles Palo Alto Networks Enterprise DLP incidents. It Collects feedback from the user about blocked activities and automates the approval process, if required. Supported communication methods are Slack, Microsoft Teams and Email.

### Sub-playbooks

* DLP - Get User Feedback
* DLP - User Message App Check
* Account Enrichment - Generic v2.1
* DLP - Get Approval
* User Investigation - Generic

### Integrations

* SlackV3
* Microsoft Teams
* Palo_Alto_Networks_Enterprise_DLP

### Scripts

EmailAskUser

### Commands

* pan-dlp-get-report
* pan-dlp-update-incident
* send-notification
* setIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ApprovalTarget | Can be either empty or one of the following:<br/>- Manager<br/>- &lt;email_address&gt;<br/>- Manual<br/><br/>"Manager" - the user's manager details will be retrieved using Active Directory enrichment and will be used for approving the exemption, if requested.<br/>&lt;email_address&gt; - the configured email address will be used for the approval process.<br/>"Manual" - Approval will be a manual task for a further review.<br/><br/>Leaving this input empty will skip the approval process. |  | Optional |
| ActionOnApproverNotFound | If the approver cannot be contacted via Slack or MS Teams, what should be the next action:<br/>- Deny<br/>- Approve<br/>- Manual | Manual | Optional |
| SendMailInstance | This input is only relevant when the "UserMessageApp" or "ApproverMessageApp" are set to "Email".<br/>The name of the instance to be used when executing the "send-mail" command in the playbook. In case it will be empty, all available instances will be used \(default\). |  | Optional |
| UserMessageApp | The communication method with the user.<br/>Can be one of the following:<br/><br/>- Slack<br/>- Microsoft Teams<br/>- Email<br/><br/>If you choose to set "Email", it's also possible to set the relevant email integration instance with the "SendEmailInstance" input. | Slack | Optional |
| ApproverMessageApp | The communication method with the approver.<br/>Can be one of the following:<br/><br/>- Slack<br/>- Microsoft Teams<br/>- Email<br/>- Manual<br/><br/>If you choose to set "Email", it's also possible to set the relevant email integration instance with the "SendEmailInstance" input. | Slack | Optional |
| DenyMessage | The message that users will receive when they are denied. | Thank you for the request. Your request was reviewed and denied. | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![DLP Incident Feedback Loop](../doc_files/DLP_Incident_Feedback_Loop.png)

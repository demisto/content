This playbook adds email details to the relevant context entities and handles original email attachments.

The v2 playbook enables parsing email artifacts more efficiently, including:
- Using incident fields and not incident labels.
- Providing separate paths to "Phishing Alerts".
- Using the new "Get Original Email - Generic v2" playbook to retrieve original emails as EML files from the following integrations:
  * EWS v2
  * Microsoft Graph Mail integration
  * Gmail
  * FireEye EX and FireEye CM
  * Proofpoint Protection Server
  * Agari Phishing Defense (EWS v2, MSGraph Mail, Gmail)
  * Mimecast


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get Original Email - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* ParseEmailFiles
* Set
* SetGridField
* IdentifyAttachedEmail
* SetAndHandleEmpty

### Commands
* setIncident
* rasterize-email

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | An EML or MSG file. | File.None | Optional |
| Email | The receiver email address. | incident.emailto | Optional |
| EmailCC | The email CC addresses. | incident.emailcc | Optional |
| EmailFrom | The sender email address. | incident.emailfrom | Optional |
| EmailSubject | The email subject. | incident.emailsubject | Optional |
| EmailText | The email text. | incident.emailbody | Optional |
| EmailHtml | The email HTML. | incident.emailhtml | Optional |
| EmailHeaders | The email headers. | incident.phishingreporteremailheaders | Optional |
| EmailFormat | The email format. | incident.emailformat | Optional |
| GetOriginalEmail | Retrieves the original email in the thread.<br/><br/>You must have the necessary permissions in your email service to execute global search.<br/><br/>- For EWS: eDiscovery<br/>- For Gmail: Google Apps Domain-Wide Delegation of Authority<br/>- For MSGraph: As described in the \[message-get API\]\(https://docs.microsoft.com/en-us/graph/api/message-get\) and the \[user-list-messages API\]\(https://docs.microsoft.com/en-us/graph/api/user-list-messages\) | False | Optional |
| MessageID | The original email message ID to retrieve. Holds the value of the "Message-ID" header of the original email. This value is passed as an input to the "Get Original Email - Generic v2" playbook. | incident.emailmessageid | Optional |
| UserID | The user's email address to retrieve the original email. This value is passed as an input to the "Get Original Email - Generic v2" playbook. | incident.emailto | Optional |
| Thread-Topic | The value of the "Thread-Topic" header which holds the original email subject, needed for forwarded email scenarios. It is passed as an input to the "Get Original Email - Generic v2" playbook to use in the relevant sub-playbooks. | incident.emailsubject | Optional |
| EmailBrand | If this value is provided, only the relevant playbook runs. If no value is provided, all sub-playbooks are run. Possible values: - Gmail - EWS v2 - MicrosoftGraphMail - EmailSecurityGateway<br/>Choosing the EmailSecurityGateway executes the following if enabled: - FireEye EX \(Email Security\) - Proofpoint TAP - Mimecast. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email.HTML | The email HTML body if it exists. | string |
| Email | The email object. | string |
| Email.CC | The email CC addresses. | string |
| Email.From | The email sender address. | string |
| Email.Subject | The email subject. | string |
| Email.To | The email receiver addresses. | string |
| Email.Text | The email text body if it exists. | string |
| Email.Headers | The full email headers as a single string. | string |
| Email.Attachments | The list of attachment names in the email. | string |
| Email.Format | The format of the email if available. | string |
| File | The file object. | string |

## Playbook Image
---
![Process Email - Generic v2](../doc_files/Process_Email_-_Generic_v2.png)
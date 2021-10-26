Add email details to the relevant context entities and handle the case where original emails are attached.

Added on this v2 playbook:
- Use incident fields and not incident labels
- Provide separate paths to "Phishing Alerts"
- Uses the new "Get Original Email - Generic v2" playbook in order to retrieve original emails as eml files for both EWS v2 and Microsoft Graph Mail integration. This will assist with parsing the email artifacts in a more efficient way.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get Original Email - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* SetGridField
* Set
* SetAndHandleEmpty
* ParseEmailFiles
* IdentifyAttachedEmail

### Commands
* rasterize-email
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | An EML or MSG file with | File.None | Optional |
| Email | The receiving email address. | incident.emailto | Optional |
| EmailCC | CC addresses. | incident.emailcc | Optional |
| EmailFrom | The originator of the email. | incident.emailfrom | Optional |
| EmailSubject | The email’s subject. | incident.emailsubject | Optional |
| EmailText | The email’s text. | incident.emailbody | Optional |
| EmailHtml | The email’s html. | incident.emailhtml | Optional |
| EmailHeaders | The email’s headers. | incident.phishingreporteremailheaders | Optional |
| EmailFormat | The email’s format. | incident.emailformat | Optional |
| GetOriginalEmail | Retrieve the original email in the thread. Default is "False".<br/><br/>You must have the necessary permissions in your email service to execute global search.<br/><br/>- EWS: eDiscovery<br/>- Gmail: Google Apps Domain-Wide Delegation of Authority<br/>- MSGraph: As described here:<br/>  \* https://docs.microsoft.com/en-us/graph/api/message-get<br/>  \* https://docs.microsoft.com/en-us/graph/api/user-list-messages | True | Optional |
| MessageID | The original email message id to retrieve. This should hold the value of the "Message-ID" header of the original email. This value will be passed as an input to the playbook "Get Original Email - Generic v2" |  | Optional |
| UserID | The user's email address which we want to retrieve the original email from. This value will be passed as an input to the playbook "Get Original Email - Generic v2". | incident.emailfrom | Optional |
| Thread-Topic | The value of the "Thread-Topic" header which holds the original email subject. This is necessary for forwarded emails scenarios. It will be passed as an input to the "Get Original Email - Generic v2" playbook in order to be used in the relevant sub-playbooks. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email.HTML | Email 'html' body if exists. | string |
| Email | Email object. | unknown |
| Email.CC | Email 'cc' addresses. | string |
| Email.From | Email 'from' sender. | string |
| Email.Subject | Email subject. | string |
| Email.To | Email 'to' addresses. | string |
| Email.Text | Email 'text' body if exists. | string |
| Email.Headers | The full email headers as a single string. | string |
| Email.Attachments | The list of attachment names in the email. | string |
| Email.Format | The format of the email if available. | string |
| File | The File object. | unknown |

## Playbook Image
---
![Process Email - Generic v2](../doc_files/Process_Email_-_Generic_v2.png)
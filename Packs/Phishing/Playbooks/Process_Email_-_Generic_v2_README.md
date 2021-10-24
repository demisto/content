Add email details to the relevant context entities and handle the case where original emails are attached.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get Original Email - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* SetGridField
* SetAndHandleEmpty
* IdentifyAttachedEmail
* ParseEmailFiles
* Set

### Commands
* setIncident
* rasterize-email

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | An EML or MSG file with | File.None | Optional |
| Email | The receiving email address. | incident.emailto | Optional |
| EmailCC | CC addresses. | incident.emailcc | Optional |
| EmailFrom | The originator of the email. | incident.emailfrom | Optional |
| EmailSubject | The email’s subject. | incident.emailsubject | Optional |
| EmailText | The email’s text. | incident.labels.emailbody | Optional |
| EmailHtml | The email’s html. | incident.emailhtml | Optional |
| EmailHeaders | The email’s headers. | incident.phishingemailthreadheaders | Optional |
| EmailFormat | The email’s format. | incident.emailformat | Optional |
| GetOriginalEmail | Retrieve the original email in the thread. Default is "False".<br/><br/>You must have the necessary permissions in your email service to execute global search.<br/><br/>- EWS: eDiscovery<br/>- Gmail: Google Apps Domain-Wide Delegation of Authority | False | Optional |
| EmailBody | The email HTML body | ${incident.emailhtml} | Optional |

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
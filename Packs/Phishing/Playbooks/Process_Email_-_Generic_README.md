Add email details to the relevant context entities and handle the case where original emails are attached.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get Original Email - Generic

### Integrations
This playbook does not use any integrations.

### Scripts
* SetAndHandleEmpty
* ParseEmailFiles
* Set
* IdentifyAttachedEmail
* SetGridField

### Commands
* rasterize-email
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | An EML or MSG file with | File.None | Optional |
| Email | The receiving email address. | incident.labels.Email | Optional |
| Email/cc | CC addresses. | incident.labels.CC | Optional |
| Email/from | The originator of the email. | incident.labels.Email/from | Optional |
| Email/subject | The email’s subject. | incident.labels.Email/subject | Optional |
| Email/text | The email’s text. | incident.labels.Email/text | Optional |
| Email/html | The email’s html. | incident.labels.Email/html | Optional |
| Email/headers | The email’s headers. | incident.labels.Email/headers | Optional |
| Email/format | The email’s format. | incident.labels.Email/format | Optional |
| GetOriginalEmail | Retrieve the original email in the thread. Default is "False".<br/><br/>You must have the necessary permissions in your email service to execute global search.<br/><br/>- EWS: eDiscovery<br/>- Gmail: Google Apps Domain-Wide Delegation of Authority | False | Optional |

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
![Process Email - Generic](https://raw.githubusercontent.com/demisto/content/82895af983e287954ef4565db548f9ae91d0487a/Packs/Phishing/doc_files/Process_Email_-_Generic.png)
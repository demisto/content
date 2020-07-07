Adds email details to the relevant context entities and handle the case where original emails are attached.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get Original Email - Generic

### Integrations
* Builtin

### Scripts
* Set
* IdentifyAttachedEmail
* ParseEmailFiles

### Commands
* setIncident
* rasterize-email

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| File | An EML or MSG file. | None | File | Optional |
| Email | The receiving email address. | labels.Email | incident | Optional |
| Email/cc | The "cc" addresses. | labels.CC | incident | Optional |
| Email/from | The originator of the email. | labels.Email/from | incident | Optional |
| Email/subject | The email’s subject. | labels.Email/subject | incident | Optional |
| Email/text | The email’s text. | labels.Email/text | incident | Optional |
| Email/html | The email’s HTML. | labels.Email/html | incident | Optional |
| Email/headers | The email’s headers. | labels.Email/headers | incident | Optional |
| Email/format | The email’s format. | labels.Email/format | incident | Optional |
| GetOriginalEmail | Returns the original email in the thread. The default is "False". You must have the necessary permissions in your email service to execute global,search. **EWS: eDiscovery** and **Gmail: Google Apps Domain-Wide Delegation of Authority**. | False | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email.HTML | The email "html" body if exists | string |
| Email | The email object. | unknown |
| Email.CC | The email "cc" addresses. | string |
| Email.From | The email "from" sender. | string |
| Email.Subject | The email subject. | string |
| Email.To | The email "to" addresses. | string |
| Email.Text | The email "text" body if exists. | string |
| Email.Headers | The full email headers as a single string. | string |
| Email.Attachments | The list of attachment names in the email. | string |
| Email.Format | The format of the email if available. | string |
| File | The file object. | unknown |

## Playbook Image
---
![Process_Email_Generic](https://raw.githubusercontent.com/demisto/content/3029b0e1168698135a20d1e934a00a30ef3f6431/Packs/Phishing/doc_files/Process_Email_-_Generic.png)

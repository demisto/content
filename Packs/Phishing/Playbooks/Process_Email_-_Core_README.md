Adds email details to the relevant context entities and handle the case where original emails are attached.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
* ParseEmailFiles
* Set
* IdentifyAttachedEmail

### Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| File | The EML or MSG file. | None | File | Optional |
| Email | The receiving email address | labels.Email | incident | Optional |
| Email/cc | THe CC addresses. | labels.CC | incident | Optional |
| Email/from | The originator of the email. | labels.Email/from | incident | Optional |
| Email/subject | The email’s subject. | labels.Email/subject | incident | Optional |
| Email/text | The email text. | labels.Email/text | incident | Optional |
| Email/html | The HTML version of the email. | labels.Email/html | incident | Optional |
| Email/headers | The email’s headers. | labels.Email/headers | incident | Optional |
| Email/format | The email’s format. | labels.Email/format | incident | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email.HTML | THe Email "HTML" body, if it exists. | string |
| Email | The email object. | unknown |
| Email.CC | The email "cc" addresses. | string |
| Email.From | The email "from" sender. | string |
| Email.Subject | The email subject. | string |
| Email.To | The email "to" addresses. | string |
| Email.Text | The email "text" body, if it exists. | string |
| Email.Headers | The full email headers as a single string. | string |
| Email.Attachments | The list of attachment names in the email. | string |
| Email.Format | The format of the email, if it is available. | string |
| File | The file object. | unknown |

## Playbook Image
---
![Process_Email_Core](https://raw.githubusercontent.com/demisto/content/3029b0e1168698135a20d1e934a00a30ef3f6431/Packs/Phishing/doc_files/Process_Email_-_Core.png)

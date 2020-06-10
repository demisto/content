Retrieves the original email in a thread, including headers and attachments, when the reporting user forwarded the original email not as an attachment.

You must have the necessary permissions in your email service to execute global search.

- EWS: eDiscovery
- Gmail: Google Apps Domain-Wide Delegation of Authority

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get Original Message - Gmail
* Get Original Email - EWS

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email | The email object. | unknown |
| File | The original attachments. | unknown |
| Email.To | The recipient of the email. | string |
| Email.From | The sender of the email. | string |
| Email.CC | The CC address of the email. | string |
| Email.BCC | The BCC address of the email. | string |
| Email.HTML | The email HTML. | string |
| Email.Body | The email text body. | string |
| Email.Headers | The email headers. | unknown |
| Email.Subject | The email subject. | string |

## Playbook Image
---
![Get_Original_Email_Generic](https://raw.githubusercontent.com/demisto/content/7a20daa4d3560df3be0d2f3f41c00d43ac1a1e23/Packs/Phishing/doc_files/Get_Original_Email_Generic.png)

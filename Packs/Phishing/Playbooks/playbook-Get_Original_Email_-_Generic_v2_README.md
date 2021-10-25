Use this playbook to retrieve the original email in the thread, including headers and attahcments, when the reporting user forwarded the original email not as an attachment.

You must have the necessary permissions in your email service to execute global search.

- EWS: eDiscovery
- Gmail: Google Apps Domain-Wide Delegation of Authority
- MSGraph: As described here:
    * https://docs.microsoft.com/en-us/graph/api/message-get
    * https://docs.microsoft.com/en-us/graph/api/user-list-messages

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get Original Email - Gmail
* Get Original Email - Microsoft Graph Mail
* Get Original Email - EWS v2

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
| Email | The email object | unknown |
| File | Original attachments | unknown |
| Email.To | The recipient of the email | string |
| Email.From | The sender of the email | string |
| Email.CC | The CC address of the email | string |
| Email.BCC | The BCC address of the email | string |
| Email.HTML | The email HTML | string |
| Email.Body | The email text body | string |
| Email.Headers | The email headers | unknown |
| Email.Subject | The email subject | string |
| Email.HeadersMap | The headers of the email. | unknown |
| reportedemailentryid | In case the original eml was retrieved, this field will hold the File's Entry ID. | unknown |

## Playbook Image
---
![Get Original Email - Generic v2](../doc_files/Get_Original_Email_-_Generic_v2.png)
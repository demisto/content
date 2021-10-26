This v2 playbook, will use the reporter email headers in order to retrieve the original email. This will assist with decreasing the amount of the tasks needed in order to do that.

Use this playbook to retrieve the original email using Gmail integration, including headers and attachments.

You must have the necessary permissions in your Gmail service to execute global search: Google Apps Domain-Wide Delegation of Authority


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Gmail

### Scripts
* Set
* IsIntegrationAvailable

### Commands
* gmail-search
* gmail-get-attachments

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MessageID | The original email message id to retrieve. This should hold the value of the "Message-ID" header of the original email and not Gmail's internal ID of the messageץ |  | Optional |
| UserID | The user's email address. The "me" special value can be used to indicate the authenticated user. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email | The email object | unknown |
| Email.To | The recipient of the email | string |
| Email.From | The sender of the email | string |
| Email.CC | The CC address of the email | string |
| Email.BCC | The BCC address of the email | string |
| Email.HTML | The email HTML | string |
| Email.Body | The email text body | string |
| Email.Headers | The email headers | string |
| Email.Subject | The email subject | string |
| File | Original attachments | unknown |

## Playbook Image
---
![Get Original Email - Gmail v2](../doc_files/Get_Original_Email_-_Gmail_v2.png)
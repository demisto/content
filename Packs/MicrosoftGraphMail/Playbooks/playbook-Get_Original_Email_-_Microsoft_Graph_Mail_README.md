This playbook retrieves the original email using the Microsoft Graph Mail integration.
Note: You must have the necessary permissions in the Microsoft Graph Mail integration as described in the [message-get API](https://docs.microsoft.com/en-us/graph/api/message-get) and the [user-list-messages API](https://docs.microsoft.com/en-us/graph/api/user-list-messages)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MicrosoftGraphMail

### Scripts
* IsIntegrationAvailable

### Commands
* msgraph-mail-get-email-as-eml
* msgraph-mail-list-emails

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| UserID | The email address of the reporting user. |  | Optional |
| MessageID | The InReplyTo header in the forwarded email. |  | Optional |
| ThreadTopic | The ThreadTopic header in the forwarded email. |  | Optional |
| PagesToPull | The number of pages of emails to return \(maximum is 10 emails per page\). | 10 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The original email as an EML file. | string |

## Playbook Image
---
![Get Original Email - Microsoft Graph Mail](../doc_files/Get_Original_Email_-_Microsoft_Graph_Mail.png)
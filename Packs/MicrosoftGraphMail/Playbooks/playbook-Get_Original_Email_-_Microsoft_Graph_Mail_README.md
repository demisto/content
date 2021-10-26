Use this playbook to retrieve the original email using Microsoft Graph Mail integration.

You must have the necessary permissions in the Microsoft Graph Mail integration as described here:
      * https://docs.microsoft.com/en-us/graph/api/message-get
      * https://docs.microsoft.com/en-us/graph/api/user-list-messages

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MicrosoftGraphMail

### Scripts
* IsIntegrationAvailable

### Commands
* msgraph-mail-list-emails
* msgraph-mail-get-email-as-eml

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| UserID | Email address of the reporting user. |  | Optional |
| MessageID | The InReplyTo header in the forwarded email. |  | Optional |
| ThreadTopic | The ThreadTopic header in the forwarded email. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The original email as eml file. | unknown |

## Playbook Image
---
![Get Original Email - Microsoft Graph Mail](../doc_files/Get_Original_Email_-_Microsoft_Graph_Mail.png)
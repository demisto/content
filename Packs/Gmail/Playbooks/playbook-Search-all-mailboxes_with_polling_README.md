This playbook searches Gmail records for all Google users. It is intended for large companies with over 2500 Google users.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Search in mailboxes Gmail (Loop) with polling

### Integrations
This playbook does not use any integrations.

### Scripts
DeleteContext

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| after | Search for messages sent after a specific date. For example, 2018/05/06 |  | Optional |
| before | Search for messages sent before a specific date. For example, 2018/05/09 |  | Optional |
| fields | Enables partial responses to be retrieved in a comma-separated list. For more information, see https://developers.google.com/gdata/docs/2.0/basics\#PartialResponse. |  | Optional |
| filename | Attachments with a certain name or file type. For example, "pdf" or "report.pdf" |  | Optional |
| from | Specifies the sender. For example, "john" |  | Optional |
| to | Specifies the receiver. For example, "john" |  | Optional |
| has-attachments | Whether to search for messages sent with attachments. |  | Optional |
| in | Messages in any folder, including Spam and Trash. For example, shopping |  | Optional |
| include-spam-trash | Includes messages from SPAM and TRASH in the results. \(Default: false\) |  | Optional |
| labels-ids | Returns messages with labels that match all of the specified label IDs in a comma-separated list. |  | Optional |
| subject | Words in the subject line. For example, "alert" |  | Optional |
| query | Returns messages matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com rfc822msgid: is:unread". For more syntax information,see "https://support.google.com/mail/answer/7190?hl=en" |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Gmail.Mailboxes | The Gmail mailbox. | unknown |
| Gmail.ID | The inner ID of the Gmail message. | unknown |
| Gmail.ThreadId | The thread ID. | unknown |
| Gmail.Format | The MIME type of the email. | unknown |
| Gmail.Labels | The labels of a specific email. | unknown |
| Gmail.To | The email address of the receiver. | unknown |
| Gmail.From | The email address of the sender. | unknown |
| Gmail.Cc | The additional recipient email address \(CC\). | unknown |
| Gmail.Bcc | The additional recipient email address \(BCC\). | unknown |
| Gmail.Subject | The subject of the specific email. | unknown |
| Gmail.Body | The content of the email. | unknown |
| Gmail.Attachments | The attachments of the email. IDs are separated by commas. | unknown |
| Gmail.Headers | All headers of a specific mail \(list\). | unknown |

## Playbook Image
---
![Search all mailboxes - Gmail with polling](../doc_files/Search_all_mailboxes_-_Gmail_with_polling.png)

This playbook is used as a subplaybook for the Playbook Search-all-mailboxes - Gmail, it should not be used.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Gmail

### Scripts
* DeleteContext
* Set

### Commands
* gmail-search-all-mailboxes

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| after | Search for messages sent after a certain time period. For example, 2018/05/06 |  | Optional |
| before | Search for messages sent before a certain time period. For example, 2018/05/09 |  | Optional |
| fields | Enables partial responses to be retrieved in a comma separated list. For more information, see https://developers.google.com/gdata/docs/2.0/basics\#PartialResponse. |  | Optional |
| filename | Attachments with a certain name or file type. For example, "pdf" or "report.pdf" |  | Optional |
| from | Specifies the sender. For example, "john" |  | Optional |
| to | Specifies the receiver. For example, "john" |  | Optional |
| has-attachments | Whether to search for messages sent with attachments. |  | Optional |
| in | Messages in any folder, including Spam and Trash. For example, shopping |  | Optional |
| include-spam-trash | Includes messages from SPAM and TRASH in the results. \(Default: false\) |  | Optional |
| labels-ids | Only returns messages with labels that match all of the specified label IDs in a comma separated list. |  | Optional |
| page-token | This argument is not usable |  | Optional |
| query | Returns messages matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com rfc822msgid: is:unread". For more syntax information,see "https://support.google.com/mail/answer/7190?hl=en" |  | Optional |
| subject | Words in the subject line. For example, "alert" |  | Optional |
| searching_accounts | Used to track a search's progress |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Gmail.Mailboxes | The Gmail Mailbox. | unknown |
| Gmail.ID | Inner ID of the Gmail message. | unknown |
| Gmail.ThreadId | The thread ID. | unknown |
| Gmail.Format | MIME type of the email. | unknown |
| Gmail.Labels | Labels of a specific email. | unknown |
| Gmail.To | Email Address of the receiver. | unknown |
| Gmail.From | Email Address of the sender. | unknown |
| Gmail.Cc | Additional recipient email address \(CC\). | unknown |
| Gmail.Bcc | Additional recipient email address \(BCC\). | unknown |
| Gmail.Subject | Subject of the specific email. | unknown |
| Gmail.Body | The content of the email. | unknown |
| Gmail.Attachments | The attachments of the email. IDs are separated by ','. | unknown |
| Gmail.Headers | All headers of specific mail \(list\). | unknown |
| Email.Attachments.entryID | Email Attachments. IDs are separated by ','. | unknown |
| NewPageToken | In the next iteration, additional accounts will be imported using this output. | unknown |
| Stop | As a result of this output, the loop will come to an end. | unknown |
| SearchingAccounts | Needs rewrite. | unknown |

## Playbook Image
---
![Search in mailboxes Gmail (Loop) with polling](../doc_files/Search_in_mailboxes_Gmail_(Loop)_with_polling.png)